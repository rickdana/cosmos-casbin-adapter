package cosmosadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos"
	"net/http"
	"strings"

	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/mmcloughlin/meow"
)

type Data struct {
	Documents interface{} `json:"Documents,omitempty"`
	Count     int         `json:"_count,omitempty"`
}

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	ID    string `json:"id"`
	PType string `json:"pType"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

// adapter represents the CosmosDB adapter for policy storage.
type adapter struct {
	containerName   string
	databaseName    string
	containerClient *azcosmos.ContainerClient
	db              *azcosmos.DatabaseClient
	client          *azcosmos.Client
	filtered        bool
}

func NewAdapterFromConnectionSting(connectionString string, options Options) persist.Adapter {
	client, err := azcosmos.NewClientFromConnectionString(connectionString, &options.ClientOptions)
	if err != nil {
		panic(fmt.Sprintf("Creating new cosmos client caused error: %s", err.Error()))
	}
	return NewAdapterFromClient(client, options)
}

// NewAdapter is the constructor for Adapter.
// if no options are given the database name is "casbin" and the containerClient is named casbin_rule
// if the database or containerClient is not found it is automatically created.
// the database can be changed by using the Database(db string) option.
// the containerClient can be changed by using the Collection(coll string) option.
// see README for example
func NewAdapter(endpoint string, cred *azidentity.DefaultAzureCredential, options Options) persist.Adapter {

	client, err := azcosmos.NewClient(endpoint, cred, &options.ClientOptions)
	if err != nil {
		panic(fmt.Sprintf("Creating new cosmos client caused error: %s", err.Error()))
	}
	return NewAdapterFromClient(client, options)
}

func NewAdapterFromClient(client *azcosmos.Client, options Options) persist.Adapter {
	// create adapter and set default values
	a := &adapter{
		containerName: options.containerName,
		databaseName:  options.databaseName,
		client:        client,
	}

	database, err := a.client.NewDatabase(options.databaseName)
	if err != nil {
		panic(fmt.Sprintf("Creating new database with id %s caused error: %s", options.databaseName, err.Error()))
	}

	container, err := a.client.NewContainer(database.ID(), options.containerName)
	if err != nil {
		panic(fmt.Sprintf("Creating container with name %s caused error: %s", options.containerName, err.Error()))
	}
	a.db = database
	a.containerClient = container
	a.databaseName = options.databaseName

	a.createDatabaseIfNotExist()
	a.createCollectionIfNotExist()
	a.filtered = false
	return a
}

func (a *adapter) createDatabaseIfNotExist() {
	ctx := context.Background()
	_, err := a.db.Read(ctx, nil)
	if err != nil {
		resErr := err.(*azcore.ResponseError)
		if resErr.StatusCode == http.StatusNotFound {
			dbProps := azcosmos.DatabaseProperties{ID: a.databaseName}
			_, createDbErr := a.client.CreateDatabase(ctx, dbProps, nil)
			if createDbErr != nil {
				panic(fmt.Sprintf("Creating cosmos database caused error: %s", createDbErr.Error()))
			}
		} else {
			panic(fmt.Sprintf("Reading cosmos database caused error: %s", err.Error()))
		}
	}

}

func (a *adapter) createCollectionIfNotExist() {
	ctx := context.Background()
	_, err := a.containerClient.Read(ctx, nil)

	if err != nil {
		resErr := err.(*azcore.ResponseError)
		if resErr.StatusCode == http.StatusNotFound {
			properties := azcosmos.ContainerProperties{
				ID: a.containerName,
				PartitionKeyDefinition: azcosmos.PartitionKeyDefinition{
					Paths: []string{"/pType"},
				},
			}
			_, err := a.db.CreateContainer(ctx, properties, nil)
			if err != nil {
				panic(fmt.Sprintf("Creating cosmos containerClient caused error: %s", err.Error()))
			}
		} else {
			panic(fmt.Sprintf("Reading cosmos containerClient caused error: %s", err.Error()))
		}
	}
}

//// NewFilteredAdapter is the constructor for FilteredAdapter.
//// Casbin will not automatically call LoadPolicy() for a filtered adapter.
//func NewFilteredAdapter(url string, options ...Option) persist.FilteredAdapter {
//	a := NewAdapter(url, options...).(*adapter)
//	a.filtered = true
//	return a
//}

func (a *adapter) dropCollection() error {
	_, err := a.containerClient.Delete(context.Background(), nil)
	if err != nil {
		return err
	}
	properties := azcosmos.ContainerProperties{
		ID: a.containerName,
		PartitionKeyDefinition: azcosmos.PartitionKeyDefinition{
			Paths: []string{"/pType"},
		},
	}
	_, err = a.db.CreateContainer(context.Background(), properties, nil)
	return err
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

// LoadPolicy loads policy from database.
func (a *adapter) LoadPolicy(model model.Model) error {
	ctx := context.Background()
	var lines []CasbinRule
	a.filtered = false
	loadPolicyQuery := "SELECT * FROM c"

	queryPager := a.containerClient.NewQueryItemsPager(loadPolicyQuery, azcosmos.NewPartitionKeyString("p"), nil)

	for queryPager.More() {
		res, err := queryPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, item := range res.Items {
			var line CasbinRule
			err := json.Unmarshal(item, &line)
			if err != nil {
				return err
			}
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}
	return nil
}

// LoadFilteredPolicy loads matching policy lines from database. If not nil,
// the filter must be a valid MongoDB selector.
func (a *adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var lines []CasbinRule
	querySpec := filter.(SqlQuerySpec)
	a.filtered = true

	queryOptions := &azcosmos.QueryOptions{
		QueryParameters: querySpec.Parameters,
	}
	queryPager := a.containerClient.NewQueryItemsPager(querySpec.Query, azcosmos.NewPartitionKeyString("p"), queryOptions)

	for queryPager.More() {
		res, err := queryPager.NextPage(context.Background())
		if err != nil {
			return err
		}
		for _, item := range res.Items {
			var line CasbinRule
			err := json.Unmarshal(item, &line)
			if err != nil {
				return err
			}
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *adapter) IsFiltered() bool {
	return a.filtered
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	line.ID = policyID(ptype, rule)
	return line
}

// SavePolicy saves policy to database.
func (a *adapter) SavePolicy(model model.Model) error {
	ctx := context.Background()

	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}
	if err := a.dropCollection(); err != nil {
		return err
	}

	var lines []CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		if err := a.save(ctx, line); err != nil {
			return err
		}
	}
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	ctx := context.Background()

	policy := savePolicyLine(ptype, rule)
	return a.save(ctx, policy)
}

func (a *adapter) save(ctx context.Context, policy CasbinRule) error {
	marshalled, err := json.Marshal(policy)

	if err != nil {
		return err
	}

	res, err := a.containerClient.CreateItem(ctx, azcosmos.NewPartitionKeyString(policy.PType), marshalled, nil)
	if err != nil {
		return err
	}

	if statusCode := res.RawResponse.StatusCode; statusCode != http.StatusCreated {
		return errors.New(fmt.Sprintf("Unable to save policy: unexpected status code %d", statusCode))
	}
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	ctx := context.Background()

	policy := savePolicyLine(ptype, rule)
	_, err := a.containerClient.DeleteItem(ctx, azcosmos.NewPartitionKeyString(policy.PType), policy.ID, nil)
	if err != nil {
		return err
	}
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx := context.Background()

	selector := make(map[string]interface{})

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	query := "SELECT * FROM root WHERE root.pType = @pType"
	parameters := []azcosmos.QueryParameter{{Name: "@pType", Value: ptype}}
	for key, value := range selector {
		query += " AND root." + key + " = @" + key
		parameters = append(parameters, azcosmos.QueryParameter{Name: "@" + key, Value: value})
	}

	var policies []CasbinRule
	queryPager := a.containerClient.NewQueryItemsPager(query, azcosmos.NewPartitionKeyString(ptype), &azcosmos.QueryOptions{QueryParameters: parameters})
	for queryPager.More() {
		res, err := queryPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, item := range res.Items {
			var policy CasbinRule
			if err := json.Unmarshal(item, &policy); err != nil {
				return err
			}
			policies = append(policies, policy)
		}
	}

	for _, policy := range policies {
		_, err := a.containerClient.DeleteItem(ctx, azcosmos.NewPartitionKeyString(policy.PType), policy.ID, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

type Options struct {
	azcosmos.ClientOptions
	databaseName  string
	containerName string
}

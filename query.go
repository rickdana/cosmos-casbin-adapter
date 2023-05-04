package cosmosadapter

import "github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos"

type QueryParam struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

type SqlQuerySpec struct {
	Query      string                    `json:"query"`
	Parameters []azcosmos.QueryParameter `json:"parameters,omitempty"`
}

func Q(query string, queryParams ...azcosmos.QueryParameter) *SqlQuerySpec {
	return &SqlQuerySpec{Query: query, Parameters: queryParams}
}

type P = QueryParam

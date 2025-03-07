package july2024august2024

import (
	"context"
	"fmt"
	"upgradationScript/2024/july2024august2024/august2024"

	"github.com/Khan/genqlient/graphql"
)

func performStatusUpdate(expDgraphClient graphql.Client) error {
	ctx := context.Background()

	if _, err := august2024.UpdateRunHistory(ctx, expDgraphClient); err != nil {
		return fmt.Errorf("error while updating runhistory status to active")
	}

	return nil

}

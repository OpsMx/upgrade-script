package july2025august2025

import (
	"context"
	"fmt"
	"time"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
	"github.com/cenkalti/backoff"
)

// callWithRetry will try your GraphQL operation up to MaxElapsedTime,
// backing off exponentially (with jitter) between attempts.
func callWithRetry(
	prodGraphUrl, prodToken string,
	operation func(ctx context.Context, gqlClient graphql.Client) error,
) error {
	// Configure an exponential backoff:
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 1 * time.Second
	exp.MaxInterval = 10 * time.Second
	exp.MaxElapsedTime = 10 * time.Minute

	attempt := 0
	// Wrap the operation so that each attempt has its own shorter timeout:
	retryOp := func() error {
		attempt++
		gqlient := graphqlfunc.NewClient(prodGraphUrl, prodToken)
		// each try gets, say, a 30s timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := operation(ctx, gqlient)
		if err != nil {
			logger.Sl.Warnf("Retry attempt %d failed: %v", attempt, err)
		}
		return err
	}

	return backoff.Retry(retryOp, exp)
}

func SetProjectLevelValueToRepositery(prodGraphUrl, prodToken string) error {

	if err := callWithRetry(prodGraphUrl, prodToken, func(ctx context.Context, gqlClient graphql.Client) error {
		_, err := SetProjectLevelToRepositery(ctx, gqlClient)
		if err != nil {
			return fmt.Errorf("error in SetProjectLevelToRepositery: %s", err.Error())
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

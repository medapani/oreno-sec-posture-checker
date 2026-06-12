package awscheck

import (
	"context"
	"time"
)

const apiCallTimeout = 5 * time.Second

func withAPITimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, apiCallTimeout)
}

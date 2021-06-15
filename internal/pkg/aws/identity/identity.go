// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package identity provides a client to make API requests to AWS Security Token Service.
package identity

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"

)

type api interface {
	GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

// STS wraps the internal sts client.
type STS struct {
	client api
}

// New returns a STS configured with the input session.
func New(s *session.Session) STS {
	return STS{
		client: sts.New(s),
	}
}

// Caller holds information about a calling entity.
type Caller struct {
	RootUserARN string
	Account     string
	UserID      string
}

// Get returns the Caller associated with the Client's session.
func (s STS) Get() (Caller, error) {
	out, err := s.client.GetCallerIdentity(&sts.GetCallerIdentityInput{})

	if err != nil {
		return Caller{}, fmt.Errorf("get caller identity: %w", err)
	}

	//TODO find a partition-neutral way to construct this ARN
	sess, err := sessions.NewProvider().Default()
	if err != nil {
		//error here
	}
	region := *sess.Config.Region
	partition := "aws"
	
	if region == "cn-north-1" || region == "cn-northwest-1" {
		partition = "aws-cn"
	}

	return Caller{
		RootUserARN: fmt.Sprintf("arn:%s:iam::%s:root", partition, *out.Account),
		Account:     *out.Account,
		UserID:      *out.UserId,
	}, nil
}

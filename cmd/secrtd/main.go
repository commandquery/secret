package main

import (
	"context"
	"fmt"
	"os"
)

// Temporary command to create a server.
func addServerCmd(hostname string) error {

	server := NewSecretServer()

	ctx := context.Background()

	_, err := PGXPool.Exec(ctx, "insert into secrt.server (server, secret_box_key, private_box_key, public_box_key, private_sign_key, public_sign_key) values ($1, $2, $3, $4, $5, $6)",
		server.Server, server.SecretBoxKey, server.PrivateBoxKey, server.PublicBoxKey, server.PrivateSignKey, server.PublicSignKey)
	if err != nil {
		return fmt.Errorf("unable to add server: %w", err)
	}

	_, err = PGXPool.Exec(ctx, "insert into secrt.hostname (hostname, server) values ($1, $2)",
		hostname, server.Server)
	if err != nil {
		return fmt.Errorf("unable to add hostname: %w", err)
	}

	return nil
}

func main() {

	mustInitPGX()
	mustInitPgpkg()

	if len(os.Args) == 3 && os.Args[1] == "add" {
		err := addServerCmd(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := StartServer(); err != nil {
		panic(err)
	}
}

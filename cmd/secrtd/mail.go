package main

import (
	"bytes"
	"fmt"
	"log"
	"text/template"

	"github.com/wneessen/go-mail"
)

const SMTP_SERVER = "smtp.postmarkapp.com"
const SMTP_USERNAME = "30fe41f5-c222-42c3-9258-5bee39bba4d5"
const SMTP_PASSWORD = "30fe41f5-c222-42c3-9258-5bee39bba4d5"
const SMTP_HEADER_KEY = "X-PM-Message-Stream"
const SMTP_HEADER_VALUE = "outbound"

const validationMessage = `
hi! thanks for trying secrt. secrt is a command line tool for sending secrets.

to activate your account, please copy and paste this into your command line:

	secrt activate {{.Token}} {{.Code}}
`

func sendmail(msg string, values any) error {
	tmpl, err := template.New("email").Parse(msg)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, values)
	if err != nil {
		return err
	}

	mailBody := buf.String()

	message := mail.NewMsg()
	if err := message.From("mark@commandquery.com"); err != nil {
		return fmt.Errorf("failed to set FROM address: %w", err)
	}

	if err := message.To("mark@commandquery.com"); err != nil {
		log.Fatalf("failed to set TO address: %s", err)
	}

	message.Subject("welcome to secrt.io!")
	message.SetBodyString(mail.TypeTextPlain, mailBody)

	// Deliver the mails via SMTP
	client, err := mail.NewClient(SMTP_SERVER,
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover), mail.WithTLSPortPolicy(mail.TLSMandatory),
		mail.WithUsername(SMTP_USERNAME), mail.WithPassword(SMTP_PASSWORD),
	)

	message.SetGenHeader(SMTP_HEADER_KEY, SMTP_HEADER_VALUE)

	if err != nil {
		log.Fatalf("failed to create new mail delivery client: %s", err)
	}

	if err := client.DialAndSend(message); err != nil {
		log.Fatalf("failed to deliver mail: %s", err)
	}

	log.Printf("Test mail successfully delivered.")

	return nil
}

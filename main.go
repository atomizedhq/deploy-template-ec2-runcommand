package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2instanceconnect"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	InstanceID      string
	InstanceOSUser  string
	InstanceCommand string
}

var (
	ec2connectSvc *ec2instanceconnect.EC2InstanceConnect
	ec2svc        *ec2.EC2
	config        *Config
)

func init() {
	log.SetFlags(log.Lshortfile)

	sesh, err := session.NewSession(aws.NewConfig())
	if err != nil {
		log.Fatal(err)
	}

	ec2svc = ec2.New(sesh)
	ec2connectSvc = ec2instanceconnect.New(sesh)

	config = &Config{
		InstanceID:      os.Getenv("INSTANCE_ID"),
		InstanceOSUser:  os.Getenv("INSTANCE_USER"),
		InstanceCommand: os.Getenv("INSTANCE_COMMAND"),
	}
}

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context) (string, error) {
	instances, err := ec2svc.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(config.InstanceID)},
	})
	if err != nil {
		log.Println(err)
		return "", err
	} else if len(instances.Reservations) == 0 || len(instances.Reservations[0].Instances) == 0 {
		err = errors.New("instance id not found")
		log.Println(err)
		return "", err
	}

	instance := instances.Reservations[0].Instances[0]
	if instance.PrivateDnsName == nil || instance.Placement == nil || instance.Placement.AvailabilityZone == nil {
		err = errors.New("invalid instance")
		log.Println(err)
		return "", err
	}

	key, keyBytes, err := generateKey()
	if err != nil {
		log.Println(err)
		return "", err
	}

	err = sendPublicKey(key, instance)
	if err != nil {
		log.Println(err)
		return "", err
	}

	client, session, err := connectToHost(config.InstanceOSUser, fmt.Sprintf("%s:22", *instance.PrivateDnsName), keyBytes)
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer client.Close()
	defer session.Close()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	err = session.Run(config.InstanceCommand)
	fmt.Println(stdoutBuf.String())
	return stdoutBuf.String(), err
}

func generateKey() (*rsa.PrivateKey, []byte, error) {
	bitSize := 4096
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, nil, err
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	return privateKey, pem.EncodeToMemory(&privBlock), nil
}

func sendPublicKey(privateKey *rsa.PrivateKey, instance *ec2.Instance) error {
	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	_, err = ec2connectSvc.SendSSHPublicKey(&ec2instanceconnect.SendSSHPublicKeyInput{
		AvailabilityZone: instance.Placement.AvailabilityZone,
		InstanceId:       instance.InstanceId,
		InstanceOSUser:   aws.String(config.InstanceOSUser),
		SSHPublicKey:     aws.String(string(pubKeyBytes)),
	})
	return err
}

func connectToHost(user, host string, pemBytes []byte) (*ssh.Client, *ssh.Session, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("parse key failed:%v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	return client, session, nil
}

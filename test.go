package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

//=========================================================================
// Affiliation of the user
//=========================================================================
const OWNER = 0     // Owner of the Identity
const CONSUMER = 1  // Anyone interested in consuming the Identity
const VALIDATOR = 2 // Entity that can certify or validate the Identity

//=========================================================================
// Identity struct
//=========================================================================
type Demographic struct {
	FName string `json:"fname"`
	MName string `json:"mname"`
	SSN   string `json:"ssn"`
}

type Identity struct {
	OwnerHash   string      `json:"hash"`
	Owner       string      `json:"owner"`
	Demographic Demographic `json:"demographic"`
	// may be extended to include other aspects of the identity
}

//==============================================================================================================================
//	 Structure Definitions
//==============================================================================================================================
//	Chaincode - A blank struct for use with Shim (A HyperLedger included go file used for get/put state
//				and other HyperLedger functions)
//==============================================================================================================================
type SimpleChaincode struct {
}

func main() {
	fmt.Println("tetete")
	test_marsh_unmarsh()
}

//=========================================================================
// Access the identity
// Who can access?
//     OWNER access without restrictions
//     VALIDATOR, CONSUMER can access only with permission
//=========================================================================
func (t *SimpleChaincode) access_identity(stub *shim.ChaincodeStub, OwnerHash string) ([]byte, error) {
	//func (t *SimpleChaincode) access_identity(stub shim.ChaincodeStubInterface, OwnerHash string) ([]byte, error) {
	_, _, err := t.get_caller_data(stub)
	if err != nil {
		return nil, errors.New("Error: Getting the caller data")
	}

	// check if affiliation allowed the access - IGNRED for time being

	// check if name allowed - IGNRED for the time being

	v, err := stub.GetState(OwnerHash)
	if err != nil {
		return nil, errors.New("Error: Retrieving the identity")
	}
	return v, nil
}

//=========================================================================
// Add the Identity
// Who can add?
//      OWNER
//=========================================================================
func (t *SimpleChaincode) create_identity(stub *shim.ChaincodeStub, identity Identity) ([]byte, error) {
	//func (t *SimpleChaincode) create_identity(stub shim.ChaincodeStubInterface, identity Identity) ([]byte, error) {

	name, affiliation, err := t.get_caller_data(stub)

	if err != nil {
		return nil, errors.New("Error: Getting the caller data")
	}

	// 1. Check the affiliation
	if affiliation != OWNER {
		fmt.Println("Error: Attemp to create identity with affiliation=" + string(affiliation))
		return nil, errors.New("Only owner of identity can create an identity.")
	}

	// 2. Check if identity already exist
	retrieved, error := stub.GetState(identity.OwnerHash)
	if error != nil {
		fmt.Println("Error: Retrieving the identity")
		return nil, errors.New("Check on identity existence failed")
	}

	if retrieved != nil {
		return nil, errors.New("Identity already exist")
	}

	// 3. Put the identity in the chain
	identity.Owner = name
	bytes, err := json.Marshal(identity)
	if err == nil {
		err = stub.PutState(identity.OwnerHash, bytes)
		if err != nil {
			fmt.Println("Error: Putting the Identinty on the chain")
		}
	} else {
		fmt.Println("Error: Marshaling of identity failed")
		return nil, errors.New("Error: Marshaling of identity failed")
	}

	return nil, nil

}

//========================================
// UTILITY Methods
//==============================================================================================================================
//	 get_caller_data - Calls the get_ecert and check_role functions and returns the ecert and role for the
//					 name passed.
//==============================================================================================================================
// func (t *SimpleChaincode) get_caller_data(stub *shim.ChaincodeStub) (string, int, error) {
func (t *SimpleChaincode) get_caller_data(stub shim.ChaincodeStubInterface) (string, int, error) {

	bytes, err := stub.GetCallerCertificate()
	if err != nil {
		return "", 0, errors.New("Couldn't retrieve caller certificate")
	}
	x509Cert, err := x509.ParseCertificate(bytes) // Extract Certificate from result of GetCallerCertificate
	if err != nil {
		return "", 0, errors.New("Couldn't parse certificate")
	}

	// 0=affiliation
	return x509Cert.Subject.CommonName, 0, nil

}

//=========================================================================
// Following are simply tester methods
// Marshal -> JSON to go
// UnMarshal ->  GO TO JSON
//=========================================================================
func test_marsh_unmarsh() {
	var test Demographic
	test.FName = "rajeev"
	test.MName = "*"
	test.SSN = "123456789"

	v, err := json.Marshal(test)

	//fmt.Println(v + error)
	if err == nil {
		os.Stdout.Write(v)
	} else {
		fmt.Println("error=", err)
	}

	err = json.Unmarshal(v, &test)

	fmt.Println(test)
}

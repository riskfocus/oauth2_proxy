package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"
)

type UserMap struct {
	usersFile string
	m         unsafe.Pointer
}

func NewUserMap(usersFile string, done <-chan bool, onUpdate func()) *UserMap {
	um := &UserMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m))
	if usersFile != "" {
		log.Printf("using authenticated emails file %s", usersFile)
		WatchForUpdates(usersFile, done, func() {
			um.LoadEmailsFile()
			onUpdate()
		})
		um.LoadEmailsFile()
	}
	return um
}

func (um *UserMap) HasEntry(email string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[email]
	return
}

func (um *UserMap) LoadEmailsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		log.Fatalf("failed opening emails-file=%q, %s", um.usersFile, err)
	}
	defer r.Close()
	csv_reader := csv.NewReader(r)
	csv_reader.Comma = ','
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true
	records, err := csv_reader.ReadAll()
	if err != nil {
		log.Printf("error reading emails-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		address := strings.ToLower(strings.TrimSpace(r[0]))
		updated[address] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated))
}

func newValidatorImpl(domains []string, usersFile string,
	bannedUsersFile string, done <-chan bool, onUpdate func()) func(string) bool {
	validUsers := NewUserMap(usersFile, done, onUpdate)
	bannedUsers := NewUserMap(bannedUsersFile, done, onUpdate)

	var allowAll bool
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
			continue
		}
		domains[i] = fmt.Sprintf("@%s", strings.ToLower(domain))
	}

	validator := func(email string) (valid bool) {
		if email == "" {
			return
		}
		email = strings.ToLower(email)
		var banned = bannedUsers.HasEntry(email)

		if banned {
			log.Printf("blocked banned email %s", email)
			return
		}

		for _, domain := range domains {
			valid = valid || strings.HasSuffix(email, domain)
		}
		if !valid {
			valid = validUsers.HasEntry(email)
		}
		if allowAll {
			valid = true
		}
		return valid
	}
	return validator
}

func NewValidator(domains []string, usersFile string, bannedUsersFile string) func(string) bool {
	return newValidatorImpl(domains, usersFile, bannedUsersFile, nil, func() {})
}

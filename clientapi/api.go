// Package clientapi defines the available API for client integration.
package clientapi

type API interface {
	// Create a Cypherlock. PIN can be empty, duration is in seconds. Secret will be autogenerated if empty.
	CreateCypherLock(passphrase, pin, secret string, duration int) (ok bool)
	// Reveal the secret within a Cypherlock.
	UnveilSecret(passphrase, pin string) (secret string, err error)
	// Destroy as much of the secret as possible, assurance returns a value between 3 and 0.
	// 3 being high assurance (servers were reached), 2 means local files were securely deleted,
	// 1 means local files were deleted without security, 0 means that the secret hasn't been destroyed.
	DestroySecret() (assurance int, ok bool)
	// Modify the duration of a cypherlock in either direction.
	ModifyDuration(passphrase, pin string, duration int) (ok bool)
	// Shorten the duration in emergencies. This relies on secure deletion.
	ShortenDuration(duration int) (assurance int, ok bool)
	// Register a callback to securely delete files
	RegisterWipe(func(filename string) (ok bool))
	// Register a callback to delete a key from the secure enclave
	RegisterKeyWipe(func(publickey string) (ok bool))
	// Register a callback to create a key
	RegisterKeyCreate(func() (publickey string, ok bool))
	// Register a callback to encrypt to a key
	RegisterKeyEncrypt(func(cleartext string, publickey string) (cyphertext string, ok bool))
	// Register a callback to decrypt with a key
	RegisterKeyDecrypt(func(cyphertext string, publickey string) (cleartext string, ok bool))

	// Worker queue. Task is a currently unique identifier. Method is one of the below, taking the given parameters.
	// Method: WipeFile. Wipe a file from the device. Only param1 is set to filename of the file.
	// Method: WipeKey. Wipe a key from the device. Only param1 is set to the public key of the key.
	// Method: CreateKey. Create a key. Must return public key.
	// Method: Encrypt. Encrypt param2 (cleartext) to the publickey in param1. Returns cyphertext.
	// Method: Decrypt. Decrypt param2 (cyphertext) with the private key that belongs to the public key given in param1. Returns cleartext.
	// Method: Idle. No tasks waiting but new tasks are expected soon. Check again.
	// Method: None. No tasks waiting and none are expected before the client triggers a new action.
	Worker() (task int, method, param1, param2, param3 string)
	// Completed signals the worker queue that a task is complete.
	Completed(task int, withError bool, returnData string)
}

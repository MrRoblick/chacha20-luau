# chacha20-luau
Api:
```luau
ChaCha20.crypt(Key: buffer, Nonce: buffer, Message: buffer, Counter: number?): buffer
```
Example:
```luau
--!strict
--!optimize 2
--!native

const ReplicatedStorage = game:GetService('ReplicatedStorage')
const EncodingService = game:GetService('EncodingService')
const ChaCha20 = require(ReplicatedStorage.ChaCha20)

const Key = buffer.fromstring("thisis32byteslongsecretkeyforu26")
const Nonce = buffer.fromstring("mycoolnonce!")
const Message = buffer.fromstring("Hello World!")

const Encrypted = ChaCha20.crypt(Key, Nonce, Message)
print(`Encrypted: {buffer.tostring(EncodingService:Base64Encode(Encrypted))}`)

const Decrypted = ChaCha20.crypt(Key, Nonce, Encrypted)
print(`Decrypted: {buffer.tostring(Decrypted)}`)
```

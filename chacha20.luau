--!strict
--!native
--!optimize 2

--[[

chacha20-luau

Author: @MrRoblick
License: MIT
Repository: https://github.com/MrRoblick/chacha20-luau

]]

const ChaCha20 = {}

@[native, checked] const function QuarterRound(State: buffer, A: number, B: number, C: number, D: number)
	local sa = buffer.readu32(State, A)
	local sb = buffer.readu32(State, B)
	local sc = buffer.readu32(State, C)
	local sd = buffer.readu32(State, D)

	sa = bit32.band(sa + sb, 0xFFFFFFFF)
	sd = bit32.lrotate(bit32.bxor(sd, sa), 16)

	sc = bit32.band(sc + sd, 0xFFFFFFFF)
	sb = bit32.lrotate(bit32.bxor(sb, sc), 12)

	sa = bit32.band(sa + sb, 0xFFFFFFFF)
	sd = bit32.lrotate(bit32.bxor(sd, sa), 8)

	sc = bit32.band(sc + sd, 0xFFFFFFFF)
	sb = bit32.lrotate(bit32.bxor(sb, sc), 7)

	buffer.writeu32(State, A, sa)
	buffer.writeu32(State, B, sb)
	buffer.writeu32(State, C, sc)
	buffer.writeu32(State, D, sd)
end

@[native, checked] const function ChaCha20Block(WorkingState: buffer, InitialState: buffer, OutBuffer: buffer)
	buffer.copy(WorkingState, 0, InitialState, 0, 64)

	for _ = 1, 10 do
		QuarterRound(WorkingState, 0, 16, 32, 48)
		QuarterRound(WorkingState, 4, 20, 36, 52)
		QuarterRound(WorkingState, 8, 24, 40, 56)
		QuarterRound(WorkingState, 12, 28, 44, 60)

		QuarterRound(WorkingState, 0, 20, 40, 60)
		QuarterRound(WorkingState, 4, 24, 44, 48)
		QuarterRound(WorkingState, 8, 28, 32, 52)
		QuarterRound(WorkingState, 12, 16, 36, 56)
	end

	for Offset = 0, 60, 4 do
		const InitWord = buffer.readu32(InitialState, Offset)
		const WorkWord = buffer.readu32(WorkingState, Offset)

		local mixedWord = bit32.band(InitWord + WorkWord, 0xFFFFFFFF)
		buffer.writeu32(OutBuffer, Offset, mixedWord)
	end
end

@[native, checked] function ChaCha20.crypt(Key: buffer, Nonce: buffer, Message: buffer, Counter: number?): buffer
	assert(buffer.len(Key) == 32, "Key must be exactly 32 bytes (256 bits)")
	assert(buffer.len(Nonce) == 12, "Nonce must be exactly 12 bytes (96 bits)")

	const InitialState = buffer.create(64)
	buffer.writestring(InitialState, 0, "expand 32-byte k")

	buffer.copy(InitialState, 16, Key, 0, 32)
	buffer.writeu32(InitialState, 48, Counter or 0)
	buffer.copy(InitialState, 52, Nonce, 0, 12)

	const WorkingState = buffer.create(64)
	const KeystreamBuf = buffer.create(64)
	const MsgLen = buffer.len(Message)
	const Result = buffer.create(MsgLen)

	local Offset = 0
	while Offset < MsgLen do
		ChaCha20Block(WorkingState, InitialState, KeystreamBuf)

		const CurrentCounter = buffer.readu32(InitialState, 48)
		buffer.writeu32(InitialState, 48, bit32.band(CurrentCounter + 1, 0xFFFFFFFF))

		const BytesToXor = math.min(64, MsgLen - Offset)

		local i = 0
		while i <= BytesToXor - 4 do
			const MsgWord = buffer.readu32(Message, Offset + i)
			const KeyWord = buffer.readu32(KeystreamBuf, i)
			buffer.writeu32(Result, Offset + i, bit32.bxor(MsgWord, KeyWord))
			i += 4
		end

		while i < BytesToXor do
			const MsgByte = buffer.readu8(Message, Offset + i)
			const KeyByte = buffer.readu8(KeystreamBuf, i)
			buffer.writeu8(Result, Offset + i, bit32.bxor(MsgByte, KeyByte))
			i += 1
		end

		Offset += BytesToXor
	end

	return Result
end

return table.freeze(ChaCha20)

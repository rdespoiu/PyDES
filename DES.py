#ROBERTO DESPOIU
#CSC 333-601

class DES:

	hexTable = dict()
	binTable = dict()
	PC1 = list()
	PC2 = list()
	IP = list()
	IP1 = list()
	EP = list()
	P = list()
	sBox = list()

	def __init__(self, plaintext, key):
		self.plaintext = plaintext
		self.key = key
		self.initTables()

	def initTables(self):
		self.hexTable = {"0000": "0", "0001": "1", "0010": "2", "0011": "3", 
						 "0100": "4", "0101": "5", "0110": "6", "0111": "7", 
						 "1000": "8", "1001": "9", "1010": "a", "1011": "b", 
						 "1100": "c", "1101": "d", "1110": "e", "1111": "f"}
					
		self.binTable = {"0": "0000", "1": "0001", "2": "0010", "3": "0011",
						 "4": "0100", "5": "0101", "6": "0110", "7": "0111",
						 "8": "1000", "9": "1001", "a": "1010", "b": "1011",
						 "c": "1100", "d": "1101", "e": "1110", "f": "1111"}

		self.PC1 = [  57, 49, 41, 33, 25, 17,  9,  1, 
			     	  58, 50, 42, 34, 26, 18, 10,  2, 
				 	  59, 51, 43, 35, 27, 19, 11,  3,
				 	  60, 52, 44, 36, 63, 55, 47, 39,
				 	  31, 23, 15,  7, 62, 54, 46, 38,
				 	  30, 22, 14,  6, 61, 53, 45, 37,
				 	  29, 21, 13,  5, 28, 20, 12,  4]

		self.PC2 = [  14, 17, 11, 24,  1,  5,  3, 28,
		         	  15,  6, 21, 10, 23, 19, 12,  4,
		         	  26,  8, 16,  7, 27, 20, 13,  2,
		         	  41, 52, 31, 37, 47, 55, 30, 40,
		         	  51, 45, 33, 48, 44, 49, 39, 56,
		         	  34, 53, 46, 42, 50, 36, 29, 32]

		self.IP      = [58, 50, 42, 34, 26, 18, 10, 2,
		           		60, 52, 44, 36, 28, 20, 12, 4,
		           		62, 54, 46, 38, 30, 22, 14, 6,
		           		64, 56, 48, 40, 32, 24, 16, 8,
		           		57, 49, 41, 33, 25, 17,  9, 1,
		           		59, 51, 43, 35, 27, 19, 11, 3,
		           		61, 53, 45, 37, 29, 21, 13, 5,
		           		63, 55, 47, 39, 31, 23, 15, 7]

		self.IP1     = [40, 8, 48, 16, 56, 24, 64, 32,
						39, 7, 47, 15, 55, 23, 63, 31,
						38, 6, 46, 14, 54, 22, 62, 30,
						37, 5, 45, 13, 53, 21, 61, 29,
						36, 4, 44, 12, 52, 20, 60, 28,
						35, 3, 43, 11, 51, 19, 59, 27,
						34, 2, 42, 10, 50, 18, 58, 26,
						33, 1, 41,  9, 49, 17, 57, 25]
		           
		self.EP      = [32,  1,  2,  3,  4,  5,
		            	 4,  5,  6,  7,  8,  9,
		            	 8,  9, 10, 11, 12, 13,
		           		12, 13, 14, 15, 16, 17,
		           		16, 17, 18, 19, 20, 21,
		           		20, 21, 22, 23, 24, 25,
		           		24, 25, 26, 27, 28, 29,
		           		28, 29, 30, 31, 32,  1]
		           
		self.P =       [16,  7, 20, 21, 29, 12, 28, 17,
		            	 1, 15, 23, 26,  5, 18, 31, 10,
		            	 2,  8, 24, 14, 32, 27,  3,  9,
		           		19, 13, 30,  6, 22, 11,  4, 25]
		           
		self.sBox = [None, None, None, None, None, None, None, None]

		self.sBox[0] = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		            	 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		            	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
		           		15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
		 
		self.sBox[1] = [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		            	 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		            	 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
		           		13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
		 
		self.sBox[2] = [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		           13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		           13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		            1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
		 
		self.sBox[3] = [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		           		13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		           		10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		            	 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
		 
		self.sBox[4] = [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		           		14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		            	 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
		           		11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
		 
		self.sBox[5] = [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		           10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		            9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		            4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
		 
		self.sBox[6] = [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		           		13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		            	 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		            	 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
		 
		self.sBox[7] = [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		            	 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		            	 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		            	 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]

	#TRANSFORM KEY
	def permuteChoiceOne(self, key, PC1):
		output = ""
		
		for choice in PC1:
			output += key[choice - 1]
		
		return [output[0:28],output[28:]]
		
	def permuteChoiceTwo(self, rotatedHalves, PC2):
		halves = rotatedHalves[0] + rotatedHalves[1]
		output = ""
		
		for choice in PC2:
			output += halves[choice - 1]
		
		return output

	def rotateLeftOneBit(self, halves):
		c1 = halves[0][1:] + halves[0][0]
		d1 = halves[1][1:] + halves[1][0]
		return [c1, d1]

	def rotateLeftTwoBits(self, halves):
		c1 = halves[0][2:] + halves[0][0:2]
		d1 = halves[1][2:] + halves[1][0:2]
		return [c1, d1]


	#INITIAL PERMUTATION OF PLAINTEXT
	def initialPermutation(self, plaintext, IP):
		output = ""
		
		for perm in IP:
			output += plaintext[perm - 1]
		
		return [output[0:32], output[32:]]

	#FINAL PERMUTATION
	def finalPermutation(self, plaintext, IP1):
		output = ""

		for perm in IP1:
			output += plaintext[perm - 1]

		#return [output[0:32], output[32:]]
		return output

	#F FUNCTION
	def expansion(self, rightSide, EP):
		output = ""
		
		for e in EP:
			output += rightSide[e - 1]
		
		return output

	def splitForSBoxes(self, rightHalf):
		assert len(rightHalf) == 48
		
		output = []
		
		while len(output) < 8:
			if len(rightHalf) == 6:
				output.append(rightHalf)
			else:
				output.append(rightHalf[0:6])
				rightHalf = rightHalf[6:]
		
		return output
		
	def processSBoxes(self, splitRightSide):

		sBox = self.sBox

		output32bit = ""
		
		for k in range(8):
			output32bit += self.sBoxOut(splitRightSide[k], sBox[k])
		
		return output32bit
			
	def sBoxOut(self, input6bit, sBoxNum):
		assert len(input6bit) == 6
		output4bit = ""
		outer = input6bit[0] + input6bit[-1]
		inner = input6bit[1:-1]
		
		outerInt = self.binToInt(int(outer))
		innerInt = self.binToInt(int(inner))
		
		output4bit = self.intToBinary(sBoxNum[(outerInt * 16) + innerInt])
		
		return output4bit
		
	def permutationP(self, input32bit, P):
		output = ""
		
		for perm in P:
			output += input32bit[perm - 1]
		
		return output
		
	def fFunction(self, rightHalf, permKey):
		EP = self.EP
		P = self.P
		
		expandedRightSide = self.expansion(rightHalf, EP)
		xorRightAndKey = self.xor(expandedRightSide, permKey)
		splitRight = self.splitForSBoxes(xorRightAndKey)
		afterSBoxes = self.processSBoxes(splitRight)
		finalPerm = self.permutationP(afterSBoxes, P)
		
		return finalPerm
		

	#TRANSFORM FOR INITIAL ROUND WITH PC1
	def transformKeyFirst(self, key):
		plaintext = self.plaintext
		PC1 = self.PC1
		PC2 = self.PC2
		
		keyPC1 = self.permuteChoiceOne(key, PC1)
		rotatedKey = self.rotateLeftOneBit(keyPC1)
		keyPC2 = self.permuteChoiceTwo(rotatedKey, PC2)
		
		return [keyPC2, rotatedKey]

	#TRANSFORM FOR ROUNDS 2, 9, 16
	def transformKeyTwoNineSixteen(self, key):
		plaintext = self.plaintext
		PC2 = self.PC2

		rotatedKey = self.rotateLeftOneBit(key)
		keyPC2 = self.permuteChoiceTwo(rotatedKey, PC2)

		return [keyPC2, rotatedKey]

	#TRANSFORM FOR ALL OTHER ROUNDS
	def transformKeyOther(self, key):
		plaintext = self.plaintext
		PC2 = self.PC2

		rotatedKey = self.rotateLeftTwoBits(key)
		keyPC2 = self.permuteChoiceTwo(rotatedKey, PC2)
			
		return [keyPC2, rotatedKey]

	#HELPER FUNCTIONS
	def intToBinary(self, num):
		return str(bin(num))[2:].zfill(4)
		
	def binToInt(self, num):
		return int('{}'.format(num),2)
		
	def xor(self, left, right):
		
		assert len(left) == len(right)
		
		output = ""
		
		for k in range(len(left)):
			if left[k] == right[k]:
				output += "0"
			else:
				output += "1"
		
		return output
		
	def splitTo4Bit(self, inp):
		assert len(inp) % 4 == 0
		
		output = []
		
		while len(inp) > 0:
			if len(inp) == 4:
				output.append(inp)
				break
			else:
				output.append(inp[0:4])
				inp = inp[4:]
			
		return output
		
	def binToHex(self, inp):
		output = ""
		
		for binChars in inp:
			output += self.hexTable[binChars]
		
		return output
		
	def hexToBin(self, inp):
		output = ""
		
		for hexChars in inp:
			output += self.binTable[hexChars]
		
		return output

	def prettyBinOutput(self, inp):
		output = ""
		
		for item in inp:
			output += "{} ".format(item)
		
		return output
		

	#ENCRYPT
	def encryptOneRound(self, plaintext, key):
		IP = self.IP
		
		#Convert hex input to binary. If the input is less than 16 chars, it will z-fill to 64 so the encryption algorithm runs smoothly
		binaryPlaintext = self.hexToBin(plaintext).zfill(64)
		binaryKey = self.hexToBin(key).zfill(64)
		
		#Performs transformation on key
		permutedKey = self.transformKeyFirst(binaryKey)[0]

		#Performs permutation of plaintext
		permutePlaintext = self.initialPermutation(binaryPlaintext, IP)
		
		#Ck and Rk
		left = permutePlaintext[0]
		right = permutePlaintext[1]
		
		#Puts Rk in Lk+1
		outputLeft = right
		
		#F Function
		fFunctionR = self.fFunction(right, permutedKey)
		
		#XORs left with the output of the f-function
		outputRight = self.xor(left, fFunctionR)
		
		#Printing it nicely
		cipherTextBinary = self.splitTo4Bit(outputLeft + outputRight)
		print("*" * 23)
		print("*Binary Representation*")
		print("*" * 23)
		print(self.prettyBinOutput(cipherTextBinary))
		print()
		print("*" * 20)
		print("*Hex Representation*")
		print("*" * 20)
		print(self.binToHex(cipherTextBinary))

		#Return the outputs
		return outputLeft + outputRight, self.binToHex(cipherTextBinary)

	def encryptAllRounds(self, plaintext, key):
		IP = self.IP
		IP1 = self.IP1

		binaryPlaintext = self.hexToBin(plaintext).zfill(64)
		binaryKey = self.hexToBin(key).zfill(64)
		nextBinaryKey = ""

		for round in range(16):
			if round == 0:
				#Performs transformation on key
				permutedKey = self.transformKeyFirst(binaryKey)[0]
				nextBinaryKey = self.transformKeyFirst(binaryKey)[1]

				#Performs permutation of plaintext
				permutePlaintext = self.initialPermutation(binaryPlaintext, IP)
				
				#Ck and Rk
				left = permutePlaintext[0]
				right = permutePlaintext[1]
				
				#Puts Rk in Lk+1
				outputLeft = right
				
				#F Function
				fFunctionR = self.fFunction(right, permutedKey)
				
				#XORs left with the output of the f-function
				outputRight = self.xor(left, fFunctionR)

				binaryPlaintext = outputLeft + outputRight
				binaryKey = permutedKey

			elif round in [1, 8, 15]:
				
				permutedKey = self.transformKeyTwoNineSixteen(nextBinaryKey)[0]

				left = binaryPlaintext[0:32]
				right = binaryPlaintext[32:]

				outputLeft = right

				fFunctionR = self.fFunction(right, permutedKey)

				outputRight = self.xor(left, fFunctionR)

				binaryPlaintext = outputLeft + outputRight
				binaryKey = permutedKey

			else:
				permutedKey = self.transformKeyOther(nextBinaryKey)[0]
				left = binaryPlaintext[0:32]
				right = binaryPlaintext[32:]

				outputLeft = right
				fFunctionR = self.fFunction(right, permutedKey)

				outputRight = self.xor(left, fFunctionR)

				binaryPlaintext = outputLeft + outputRight
				binaryKey = permutedKey

		finalCiphertext = self.finalPermutation(binaryPlaintext, IP1)

		cipherTextBinary = self.splitTo4Bit(finalCiphertext)

		print("*" * 23)
		print("*Binary Representation*")
		print("*" * 23)
		print(self.prettyBinOutput(cipherTextBinary))
		print()
		print("*" * 20)
		print("*Hex Representation*")
		print("*" * 20)
		print(self.binToHex(cipherTextBinary))


def main():
	while True:
		print("Would you like to perform 1 or sixteen rounds of encryption? Enter 1 or 16")
		oneOrSixteen = input(">  ")

		print("Please enter a 16 character hexadecimal plaintext")
		plaintext = input(">  ")
		print("Please enter a 16 character hexadecimal key")
		key = input(">  ")
		
		if (len(plaintext) > 16 or len(key) > 16):
			print("***Please enter a max of 16 characters!***\n" * 5)
		else:
			if oneOrSixteen == "1":
				#Initialize a DES object
				des = DES(plaintext, key)

				#Perform encryption
				des.encryptOneRound(plaintext, key)

			elif oneOrSixteen == "16":
				#Initialize a DES object
				des = DES(plaintext, key)

				#Perform 16 rounds of encryption
				des.encryptAllRounds(plaintext, key)

			else:
				print("Please enter 1 or 16")

			print("Continue? y / n")
			cont = input(">  ")
			if cont == "n":
				break

if __name__ == "__main__":
	main()
from AES_Class import AESBlock

def xor(block1, block2):
  result = ''
  for i in range(len(block1)):
    result = result + hex(int(block1[i],16) ^ int(block2[i],16))[2]
  return result

def stringFilaBlock(block):
  result = '[ '
  for i in range(4):
    for j in range(4):
      result =  result + hex(block[j][i])[2:].zfill(2)
    result = result + ' | '
  result = result + ' ] '
  return result

def transformString(block):
  result = ''
  for i in range(4):
    for j in range(4):
      result = result + hex(block[i][j])[2:].zfill(2) 
  return result


# print('Entrada:')
# clave = str(input('      Clave: '))
# iv = str(input('      IV: '))
# bloque1Original = str(input('      Bloque 1 de Texto Original: '))
# bloque2Original = str(input('      Bloque 2 de Texto Original: '))

clave = '000102030405060708090A0B0C0D0E0F'
iv = '00000000000000000000000000000000'
bloque1Original = '00112233445566778899AABBCCDDEEFF'
bloque2Original = '000000000000000000000000000000'

print('Salida:')

if (len(bloque2Original) == 32 ):
  # Definimos la clase bloque:

  Block = AESBlock(clave)

  # Corresponde al primer bloque de cifrado:

  xor1 = xor(bloque1Original, iv)

  bloque1Cifrado = Block.run(xor1)

  bloque1CifradoString = transformString(bloque1Cifrado)

  print('       Bloque 1 de Texto Cifrado: ', end='')
  print(bloque1CifradoString)


  # Corresponde con el segundo bloque de cifrado:

  xor2 = xor(bloque1CifradoString, bloque2Original)

  bloque2Cifrado = Block.run(xor2)

  bloque2CifradoString = transformString(bloque2Cifrado)

  print('       Bloque 2 de Texto Cifrado: ', end='')
  print(bloque2CifradoString)

else:
    # Definimos la clase bloque:
  copybloque2Original = bloque2Original
  bloque2Original = bloque2Original.ljust(32, '0')
  Block = AESBlock(clave)

  # Corresponde al primer bloque de cifrado:

  xor1 = xor(bloque1Original, iv)

  bloque1Cifrado = Block.run(xor1)

  bloque1CifradoString = transformString(bloque1Cifrado)



  # Corresponde con el segundo bloque de cifrado:

  xor2 = xor(bloque1CifradoString, bloque2Original)

  bloque2Cifrado = Block.run(xor2)

  bloque2CifradoString = transformString(bloque2Cifrado)

  print('       Bloque 1 de Texto Cifrado: ', end='')
  print(bloque2CifradoString)

  print('       Bloque 2 de Texto Cifrado: ', end='')
  print(bloque1CifradoString[:len(copybloque2Original)].ljust(32,'-'))
  

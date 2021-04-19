class AESBlock:
  def __init__(self, keyArgument):
    self.sBox = []
    self.sBox.append([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])
    self.sBox.append([0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0])
    self.sBox.append([0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15])
    self.sBox.append([0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75])
    self.sBox.append([0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84])
    self.sBox.append([0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf])
    self.sBox.append([0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8])
    self.sBox.append([0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2])
    self.sBox.append([0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73])
    self.sBox.append([0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb])
    self.sBox.append([0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79])
    self.sBox.append([0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08])
    self.sBox.append([0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a])
    self.sBox.append([0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e])
    self.sBox.append([0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf])
    self.sBox.append([0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16])

    # Se usa para la expansión de claves constant RC
    self.rc = []
    self.rc.append([0x01, 0x00, 0x00, 0x00])
    self.rc.append([0x02, 0x00, 0x00, 0x00])
    self.rc.append([0x04, 0x00, 0x00, 0x00])
    self.rc.append([0x08, 0x00, 0x00, 0x00])
    self.rc.append([0x10, 0x00, 0x00, 0x00])
    self.rc.append([0x20, 0x00, 0x00, 0x00])
    self.rc.append([0x40, 0x00, 0x00, 0x00])
    self.rc.append([0x80, 0x00, 0x00, 0x00])
    self.rc.append([0x1b, 0x00, 0x00, 0x00])
    self.rc.append([0x36, 0x00, 0x00, 0x00])
    #KEY:
    self.key = []
    for i in range(4):
      self.key.append([])
      for j in range(4):
        pos = (i * 8) + (2 * j)  # Coges dos valores porque es hexadecimal
        self.key[i].append(int(keyArgument[pos:pos+2], 16))
    
    self.subclave = []
    self.subclave.append(self.key)
    for n in range(0, 10):
      clave_aux = []
      columna_aux = []
      columna1 = []
      columna2 = []
      columna3 = []
      columna4 = []
      
      for i in range(4):
        columna_aux.append(self.subclave[n][3][i]) #Cogemos la última columna de la subclave

      #RotWord
      aux = columna_aux.pop(0)
      columna_aux.append(aux)

      #SubBytes
      self.sub_bytes_col(columna_aux)

      #XOR
      for i in range(4):
        columna1.append(self.subclave[n][0][i] ^ columna_aux[i] ^ self.rc[n][i])  # Recuerda que calculas las 4 filas de las columnas
        columna2.append(self.subclave[n][1][i] ^ columna1[i])
        columna3.append(self.subclave[n][2][i] ^ columna2[i])
        columna4.append(self.subclave[n][3][i] ^ columna3[i])
      clave_aux.append(columna1)
      clave_aux.append(columna2)
      clave_aux.append(columna3)
      clave_aux.append(columna4)
      self.subclave.append(clave_aux)  # Se añade la subclave generada a la lista de claves
      

  #-------------------------------------------------------------------------------------------------
  # Funciones:
  # Función SubBytes (para columnas): Sustitución no lineal de los bytes del vector
  # basada en una S-Caja que, para cada byte, genera un nuevo byte
  def sub_bytes_col(self, columna):
    for i in range(4):
      if len(hex(columna[i])[2:]) == 1:  # Si el número hexadecimal tiene una sola cifra...
        coord1 = 0
        coord2 = columna[i]
      else:
        coord1 = int(hex(columna[i])[-2], 16)  # -2 indica la penúltima posición
        coord2 = int(hex(columna[i])[-1], 16)  # -1 indica la última posición
      columna[i] = self.sBox[coord1][coord2]

  # Función SubBytes: Sustitución no lineal de los bytes de la matriz de estado 
  # basada en una S-Caja que, para cada byte, genera un nuevo byte
  def sub_bytes(self, estado):
    for i in range(4):
      for j in range(4):
        if len(hex(estado[i][j])[2:]) == 1:  # Si el número hexadecimal tiene una sola cifra...
          coord1 = 0
          coord2 = estado[i][j]
        else:
          coord1 = int(hex(estado[i][j])[-2], 16)  # -2 indica la penúltima posición
          coord2 = int(hex(estado[i][j])[-1], 16)  # -1 indica la última posición
        estado[i][j] = self.sBox[coord1][coord2]

  # Función ShiftRow: Desplaza a la izquierda los bytes tantas veces como
  # indique su posición en la matriz de las filas que conforman
  # la matriz del estado pasado por parámetros // izquierda
  def shift_rows(self, estado):
    for i in range(4):
      for j in range(i):
        aux1 = estado[0].pop(i)
        aux2 = estado[1].pop(i)
        aux3 = estado[2].pop(i)
        aux4 = estado[3].pop(i)
        estado[0].insert(i, aux2)
        estado[1].insert(i, aux3)
        estado[2].insert(i, aux4)
        estado[3].insert(i, aux1)

  # Función MixColumn
  def mix_column(self, r):
    a = []
    b = []
    for c in range(4):
      a.append(r[c])
      h = r[c] & 0x80
      b.append((r[c] << 1) % 256)
      if h == 0x80:
        b[c] = b[c] ^ 0x1b
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]

  # Función AddRoundKey: Consiste en una XOR entre
  # el estado intermedio y la subclave correspondientes
  def add_round_key(self, entrada, clave):
    for i in range(4):
      columna_intermedia = []
      for j in range(4):
        columna_intermedia.append(entrada[i][j] ^ clave[i][j])
      entrada[i] = columna_intermedia
  
  def stringFilaBlock(self, block):
    result = '[ '
    for i in range(4):
      for j in range(4):
        result =  result + hex(block[j][i])[2:].zfill(2)
      result = result + ' | '
    result = result + ' ] '
    return result
        

  def run(self, originalTextArgument):
    #Original Text:
    self.originalText = []
    for i in range(4):
      self.originalText.append([])
      for j in range(4):
        pos = (i * 8) + (2 * j)
        self.originalText[i].append(int(originalTextArgument[pos:pos+2], 16))
    intermedio = []  # Lista en la que se irán guardando los estados intermedios
    # Primera iteración (solo AddRoundKey)
    estado_aux = self.originalText  # Estado auxiliar que se transformará hasta obtener el primer estado intermedio
    self.add_round_key(estado_aux, self.key)  # AddRoundKey entre el bloque de entrada y la clave original
    intermedio.append(estado_aux)  # Se guarda el primer estado intermedio generado


    # 9 iteraciones (1.SubBytes, 2.ShiftRow, 3.MixColumn y 4.AddRoundKey)
    for a in range(1, 10):
      estado_aux = intermedio[a-1]  # Estado auxiliar que se transformará hasta obtener el estado intermedio correspondiente
      self.sub_bytes(estado_aux)  # 1.SubBytes

      self.shift_rows(estado_aux)  # 2.ShiftRows

      for i in range(4):
        self.mix_column(estado_aux[i])  # 3.MixColumn con cada una de las columnas del estado

      self.add_round_key(estado_aux, self.subclave[a])  # 4.AddRoundKey con la subclave correspondiente

      intermedio.append(estado_aux)  # Se guarda el estado intermedio generado



      # Última iteración (1.SubBytes, 2.ShiftRows, 3.AddRoundKey)
    estado_aux = intermedio[-1]  # Estado auxiliar que se transformará hasta obtener el último estado intermedio
    self.sub_bytes(estado_aux)  # 1.SubBytes
    self.shift_rows(estado_aux)  # 2.ShiftRows
    self.add_round_key(estado_aux, self.subclave[-1])  # AddRoundKey con la última subclave
    intermedio.append(estado_aux)  # Se guarda el último estado intermedio generado
 
    return intermedio[-1]

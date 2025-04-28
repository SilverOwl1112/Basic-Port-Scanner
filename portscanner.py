import nmap

begin=1
end=65535

target=raw_input("Enter your target: ")

scanner=nmap.PortScanner()

for i in range(begin,end+1):

  res-scanner.scan(target,star(i))

  res=res['scan'][target]['tcp'][i]['state']

  print('Port:',i,'State:',res)

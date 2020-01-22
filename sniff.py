import pcap
from binascii import hexlify, unhexlify
from protocols import ethernet, ip, tcp
import protocols
sniff_interface = pcap.lookupdev()

#ssl_bpf = pcap.bpf('port 443')

p = pcap.pcap(sniff_interface)
#p.setfilter(ssl_bpf)
p.setnonblock()
eth = ethernet()
ipt = ip()
tcpt = tcp()
recvd = 0
for tm, pkt in p:
    if recvd == 100:
        break
    ethprot = protocols.quickEthernetProto(pkt[:14])
    if ethprot != 0x0800:
        continue
    ihl = protocols.quickIPhlen(pkt[14:]) * 4
    pktlen = protocols.quickIPpktlen(pkt[14:]) - ihl 
    ipproto = protocols.quickIPProto(pkt[14:])
    ipend = 14 + ihl
    if ipproto != 6:
        continue
    tcpsource = protocols.quickTCPSourcePort(pkt[ipend:])
    tcpdest = protocols.quickTCPDestPort(pkt[ipend:])
    if tcpsource != 25565 and tcpdest != 25565:
        continue
    tcpt.update(pkt[ipend:])
    recvd += 1
    print '\nNew packet!'
    print 'IP protocol: ' + str(ipproto)
    print 'Ethernet protocol: ' + hex(ethprot)
    print 'TCP: '
    tcpparams = tcpt.getAllParams()
    print tcpparams
    print 'Data length: ' + str(pktlen - tcpt.getHeaderLen() * 4)
    dat = pkt[ipend + tcpt.getHeaderLen() * 4:]
    print 'Data hex: ' + hexlify(dat)
    print 'Data: ' + dat
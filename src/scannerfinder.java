import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import java.util.*;


public class scannerfinder {

    public static void main(String[] args){
        ArrayList<String> sent = new ArrayList<>();
        Map<String, Integer> countS = new HashMap<>();
        ArrayList<String> received = new ArrayList<>();
        Map<String, Integer> countR = new HashMap<>();
        StringBuilder errors = new StringBuilder();
        Tcp tcp = new Tcp();
        Ip4 ip = new Ip4();

        Pcap pcap = Pcap.openOffline("capture.pcap", errors);

        PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket pcapPacket, String s) {
                if(pcapPacket.hasHeader(ip) && pcapPacket.hasHeader(tcp)){
                    if (tcp.flags_SYN()){
                        sent.add(FormatUtils.ip(ip.source()));
                        received.add(FormatUtils.ip(ip.destination()));
                    }
                    if (tcp.flags_ACK()){
                        received.add(FormatUtils.ip(ip.destination()));
                    }
                }
            }
        };

        try{
            pcap.loop(-1, handler, "");
        } finally { pcap.close(); }

        for (String tempS : sent){
            if (countS.containsKey(tempS)){
                countS.replace(tempS, countS.get(tempS) + 1);
            }
            else
                countS.put(tempS, 1);
        }

        for (String tempR : received){
            if (countR.containsKey(tempR)){
                countR.replace(tempR, countR.get(tempR) + 1);
            }
            else
                countR.put(tempR, 1);
        }

        System.out.println("SENT IP's");
        for (String s : countS.keySet()){
            System.out.println(s + "       " + countS.get(s));
        }

        System.out.println("RECEIVED IP's");
        for (String s : countR.keySet()){
            System.out.println(s);
        }

        System.out.println("Ip's w/ 3x more syn sent than syn+ack received");
        for (String tempS : countS.keySet()){
            if (Arrays.asList(countR.keySet()).contains(tempS) && countS.get(tempS) > 3*countR.get(tempS)){
                System.out.println(tempS);
            }
        }
    }
}

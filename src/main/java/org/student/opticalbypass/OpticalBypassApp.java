package org.student.opticalbypass;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.*;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component(immediate = true)
public class OpticalBypassApp {
    private static final Logger log = LoggerFactory.getLogger(OpticalBypassApp.class);
    private static final String APP_NAME = "org.student.opticalbypass";

    private static final int FLOW_TIMEOUT = 30; // seconds
    private static final Set<DeviceId> TOR_SWITCHES = new HashSet<>(
      Arrays.asList(
              DeviceId.deviceId("of:0000000000000001"),
              DeviceId.deviceId("of:0000000000000002"),
              DeviceId.deviceId("of:0000000000000003"),
              DeviceId.deviceId("of:0000000000000004")
      ));
    private static final DeviceId SPINE_ELECTRICAL = DeviceId.deviceId("of:0000000000000005");
    private static final DeviceId SPINE_OPTICAL = DeviceId.deviceId("of:0000000000000006");

    // FTP, Telnet, SSH, iPerf qualifies for optical bypass
    private static final Set<Integer> OPTICAL_BYPASS_ALLOWED_TCP_PORTS = new HashSet<>(Arrays.asList(20, 21, 22, 5001));

    ArrayList<TrafficSelector> aclRules  =  new ArrayList<>();
    private static final int PRIORITY_LOCAL = 40000;
    private static final int PRIORITY_OPTICAL = 30000;
    private static final int PRIORITY_ELECTRICAL = 20000;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new OpticalBypassPacketProcessor();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        packetService.addProcessor(packetProcessor, PacketProcessor.director(2));

        // Request IPv4 packets
        packetService.requestPackets(
                DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .build(),
                PacketPriority.REACTIVE,
                appId
        );

        log.info("Started {}", APP_NAME);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(appId);
        log.info("Stopped {}", APP_NAME);
    }

    private class OpticalBypassPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            ConnectPoint srcConnectPoint = pkt.receivedFrom();
            Host dstHost = hostService.getHost(HostId.hostId(ethPkt.getDestinationMAC()));

            if (dstHost == null) {
                return;
            }

            DeviceId srcTor = srcConnectPoint.deviceId();
            DeviceId dstTor = dstHost.location().deviceId();

            // Handle local traffic (same TOR)
            if (srcTor.equals(dstTor)) {
                log.info(
                        "Local traffic from {} to {} connected via TOR {}",
                        ethPkt.getSourceMAC(),
                        ethPkt.getDestinationMAC(),
                        srcTor
                );
                handleLocalTraffic(context, dstHost);
            }

            /* Handle leaf-spine traffic
            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();

            handleNonLocalTraffic(context, srcTor, dstTor, dstHost, ipv4Packet);
            */
        }

        private void handleLocalTraffic(PacketContext context, Host dstHost) {
            InboundPacket pkt = context.inPacket();
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchEthDst(dstHost.mac())
                    .build();
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(dstHost.location().port())
                    .build();
            FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(pkt.receivedFrom().deviceId())
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withPriority(PRIORITY_LOCAL)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .build();

            flowRuleService.applyFlowRules(flowRule);

            // Update statistics
            String flowId = String.format("local-%s-%s", pkt.receivedFrom().deviceId(), dstHost.location().deviceId());
            updateFlowStats(flowId, "local");

            packetOut(context, dstHost.location().port());
        }

        private void handleNonLocalTraffic(
                PacketContext context,
                DeviceId srcTor,
                DeviceId dstTor,
                Host dstHost,
                IPv4 ipv4Packet
        ) {
            String pathType = "optical";
            DeviceId spine = qualifiesForOpticalBypass(ipv4Packet)
                    ? SPINE_OPTICAL
                    : SPINE_ELECTRICAL;
            PortNumber rxPort = getSpinePort(srcTor, spine);
            PortNumber txPort = getSpinePort(dstTor, spine);

            if (!isOpticalPathAvailable(rxPort, txPort)) {
                pathType = "electrical";
                spine = SPINE_ELECTRICAL;
                rxPort = getSpinePort(srcTor, spine);
                txPort = getSpinePort(dstTor, spine);
            }

            installFlowRules(context, srcTor, spine, dstTor, rxPort, txPort, dstHost);

            // Update statistics
            String flowId = String.format("%s-%s-%s", pathType, srcTor, dstTor);
            updateFlowStats(flowId, pathType);

            context.block();
        }

        private boolean qualifiesForOpticalBypass(IPv4 ipv4Packet) {
            if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_TCP)
                return false;

            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
            int dstPort = tcpPacket.getDestinationPort();

            return OPTICAL_BYPASS_ALLOWED_TCP_PORTS.contains(dstPort);
        }


        private void installFlowRules(
                PacketContext context,
                DeviceId srcTor,
                DeviceId spine,
                DeviceId dstTor,
                PortNumber rxPort,
                PortNumber txPort,
                Host dstHost
        ) {
            int priority = spine.equals(SPINE_OPTICAL)
                    ? PRIORITY_OPTICAL
                    : PRIORITY_ELECTRICAL;


            // Source ToR to Spine
            FlowRule srcRule = DefaultFlowRule.builder()
                    .forDevice(srcTor)
                    .withSelector(createSelector(context.inPacket(), dstHost))
                    .withTreatment(DefaultTrafficTreatment.builder()
                            .setOutput(rxPort)
                            .build())
                    .withPriority(priority)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .build();

            // Spine to Destination ToR
            FlowRule spineRule = DefaultFlowRule.builder()
                    .forDevice(spine)
                    .withSelector(createSelector(context.inPacket(), dstHost))
                    .withTreatment(DefaultTrafficTreatment.builder()
                            .setOutput(txPort)
                            .build())
                    .withPriority(priority)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .build();

            // Destination ToR to Host
            FlowRule dstRule = DefaultFlowRule.builder()
                    .forDevice(dstTor)
                    .withSelector(createSelector(context.inPacket(), dstHost))
                    .withTreatment(DefaultTrafficTreatment.builder()
                            .setOutput(dstHost.location().port())
                            .build())
                    .withPriority(priority)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .build();

            flowRuleService.applyFlowRules(srcRule, spineRule, dstRule);
        }

        private TrafficSelector createSelector(InboundPacket pkt, Host dstHost) {
            Ethernet ethPkt = pkt.parsed();
            return DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchEthDst(dstHost.mac())
                    .build();
        }

        private PortNumber getSpinePort(DeviceId torId, DeviceId spineId) {
            // TODO: Implementation to get correct spine port based on the topology
            return PortNumber.portNumber(1); // Placeholder
        }

        private boolean isOpticalPathAvailable(PortNumber srcPort, PortNumber dstPort) {
            // TODO: implement this functionality
            return false;
        }

        private void updateFlowStats(String flowId, String pathType) {
            // TODO: implement this functionality
            //flowStats.computeIfAbsent(flowId, k -> new FlowStats()).incrementCount(pathType);
        }

        private void packetOut(PacketContext context, PortNumber portNumber) {
            context.treatmentBuilder().setOutput(portNumber);
            context.send();
        }
    }
}
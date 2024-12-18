package org.student.opticalbypass;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.*;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true)
public class OpticalBypassApp {
    private final PacketProcessor packetProcessor = new OpticalBypassPacketProcessor();
    private final Logger log = LoggerFactory.getLogger(OpticalBypassApp.class);
    private final String APP_NAME = "org.student.opticalbypass";
    private final int FLOW_TIMEOUT = 20; // seconds
    private final int PRIORITY_LOCAL = 30;
    private final int PRIORITY_OPTICAL = 20;
    private final int PRIORITY_ELECTRICAL = 10;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    private ApplicationId appId;
    private DeviceId SPINE_ELECTRICAL;
    private DeviceId SPINE_OPTICAL;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        int deviceCount = deviceService.getDeviceCount();
        SPINE_ELECTRICAL = DeviceId.deviceId(String.format("of:%016x", deviceCount-1));
        SPINE_OPTICAL = DeviceId.deviceId(String.format("of:%016x", deviceCount));

        packetService.addProcessor(packetProcessor, PacketProcessor.director(2));

        // Request IPv4 packets
        packetService.requestPackets(
                DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .build(),
                PacketPriority.REACTIVE,
                appId);

        log.info("ELECTRICAL SPINE ID {}", SPINE_ELECTRICAL);
        log.info("OPTICAL SPINE ID {}", SPINE_OPTICAL);
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
            if (context.isHandled()) return;

            // Parse ethernet packet
            Ethernet ethPkt = context.inPacket().parsed();

            // Get source and destination hosts
            Host srcHost = hostService.getHost(HostId.hostId(ethPkt.getSourceMAC()));
            Host dstHost = hostService.getHost(HostId.hostId(ethPkt.getDestinationMAC()));

            // Get source and destination leaf(s)
            DeviceId srcLeaf = srcHost.location().deviceId();
            DeviceId dstLeaf = dstHost.location().deviceId();

            if (srcLeaf.equals(dstLeaf)) {
                handleIntraLeafTraffic(context, srcHost, dstHost);
            } else {
                HandleInterLeafTraffic(context, srcLeaf, dstLeaf);
            }
        }

        private void handleIntraLeafTraffic(PacketContext context, Host srcHost, Host dstHost) {
            log.info("Processing intra-leaf traffic: src MAC={}, dst MAC={}, leaf deviceId={}",
                    srcHost.mac(), dstHost.mac(), srcHost.location().deviceId());

            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchInPort(srcHost.location().port())
                    .matchEthSrc(srcHost.mac())
                    .matchEthDst(dstHost.mac())
                    .build();
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(dstHost.location().port())
                    .build();
            FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(srcHost.location().deviceId())
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withPriority(PRIORITY_LOCAL)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .build();

            flowRuleService.applyFlowRules(flowRule);
            context.treatmentBuilder().setOutput(dstHost.location().port());
            context.send();
        }

        private void HandleInterLeafTraffic(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf) {
            log.info("Processing inter-leaf traffic: src leaf={}, dst leaf={}", srcLeaf, dstLeaf);

            if (isEligibleForOpticalPath(context) && isOpticalPathAvailable(srcLeaf, dstLeaf)) {
                log.info("Routing via Optical Spine");
                routeViaSpine(context, srcLeaf, dstLeaf, SPINE_OPTICAL, PRIORITY_OPTICAL);
            } else {
                log.info("Routing via Electrical Spine");
                routeViaSpine(context, srcLeaf, dstLeaf, SPINE_ELECTRICAL, PRIORITY_ELECTRICAL);
            }
        }
    }

    private void routeViaSpine(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf, DeviceId spineDeviceId,
            int priority) {
        // Parse Ethernet frame and payload (IPv4 packet)
        Ethernet ethPkt = context.inPacket().parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();

        // Get the ports in the circuit
        PortNumber srcLeafUplink = getConnectingPort(srcLeaf, spineDeviceId);
        PortNumber spineToDestPort = getConnectingPort(spineDeviceId, dstLeaf);
        PortNumber dstLeafDownlink = getHostFacingPort(dstLeaf, IpAddress.valueOf(ipv4Pkt.getDestinationAddress()));

        PortNumber dstLeafUplink = getConnectingPort(dstLeaf, spineDeviceId);
        PortNumber spineToSrcPort = getConnectingPort(spineDeviceId, srcLeaf);
        PortNumber srcLeafDownlink = getHostFacingPort(srcLeaf, IpAddress.valueOf(ipv4Pkt.getSourceAddress()));

        TrafficSelector forwardSelector;
        TrafficSelector reverseSelector;

        // Match the appropriate protocol and fields for forward and reverse flows
        switch (ipv4Pkt.getProtocol()) {
            case IPv4.PROTOCOL_TCP: // Protocol number 6 for TCP
                TCP tcpPkt = (TCP) ipv4Pkt.getPayload();
                forwardSelector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchEthSrc(ethPkt.getSourceMAC())
                        .matchEthDst(ethPkt.getDestinationMAC())
                        .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getSourceAddress()), 32))
                        .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getDestinationAddress()), 32))
                        .matchIPProtocol(IPv4.PROTOCOL_TCP)
                        .matchTcpSrc(TpPort.tpPort(tcpPkt.getSourcePort()))
                        .matchTcpDst(TpPort.tpPort(tcpPkt.getDestinationPort()))
                        .build();
                reverseSelector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchEthSrc(ethPkt.getDestinationMAC())
                        .matchEthDst(ethPkt.getSourceMAC())
                        .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getDestinationAddress()), 32))
                        .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getSourceAddress()), 32))
                        .matchIPProtocol(IPv4.PROTOCOL_TCP)
                        .matchTcpSrc(TpPort.tpPort(tcpPkt.getDestinationPort()))
                        .matchTcpDst(TpPort.tpPort(tcpPkt.getSourcePort()))
                        .build();
                break;

            default:
                forwardSelector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchEthSrc(ethPkt.getSourceMAC())
                        .matchEthDst(ethPkt.getDestinationMAC())
                        .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getSourceAddress()), 32))
                        .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getDestinationAddress()), 32))
                        .matchIPProtocol(ipv4Pkt.getProtocol())
                        .build();
                reverseSelector = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchEthSrc(ethPkt.getDestinationMAC())
                        .matchEthDst(ethPkt.getSourceMAC())
                        .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getDestinationAddress()), 32))
                        .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getSourceAddress()), 32))
                        .matchIPProtocol(ipv4Pkt.getProtocol())
                        .build();
                break;
        }

        // Create port-based treatments for forward and reverse paths
        TrafficTreatment forwardTreatmentSrcLeaf = DefaultTrafficTreatment.builder()
                .setOutput(srcLeafUplink)
                .build();
        TrafficTreatment forwardTreatmentSpine = DefaultTrafficTreatment.builder()
                .setOutput(spineToDestPort)
                .build();
        TrafficTreatment forwardTreatmentDstLeaf = DefaultTrafficTreatment.builder()
                .setOutput(dstLeafDownlink)
                .build();

        TrafficTreatment reverseTreatmentDstLeaf = DefaultTrafficTreatment.builder()
                .setOutput(dstLeafUplink)
                .build();
        TrafficTreatment reverseTreatmentSpine = DefaultTrafficTreatment.builder()
                .setOutput(spineToSrcPort)
                .build();
        TrafficTreatment reverseTreatmentSrcLeaf = DefaultTrafficTreatment.builder()
                .setOutput(srcLeafDownlink)
                .build();

        // Create flow rules for forward path
        FlowRule forwardFlowRuleSrcLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(srcLeaf)
                .withSelector(forwardSelector)
                .withTreatment(forwardTreatmentSrcLeaf)
                .withPriority(priority)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule forwardFlowRuleSpine = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(spineDeviceId)
                .withSelector(forwardSelector)
                .withTreatment(forwardTreatmentSpine)
                .withPriority(priority)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule forwardFlowRuleDstLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(dstLeaf)
                .withSelector(forwardSelector)
                .withTreatment(forwardTreatmentDstLeaf)
                .withPriority(priority)
                .makeTemporary(FLOW_TIMEOUT)
                .build();

        // Create flow rules for reverse path
        FlowRule reverseFlowRuleDstLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(dstLeaf)
                .withSelector(reverseSelector)
                .withTreatment(reverseTreatmentDstLeaf)
                .withPriority(priority)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule reverseFlowRuleSpine = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(spineDeviceId)
                .withSelector(reverseSelector)
                .withTreatment(reverseTreatmentSpine)
                .withPriority(priority)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule reverseFlowRuleSrcLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(srcLeaf)
                .withSelector(reverseSelector)
                .withTreatment(reverseTreatmentSrcLeaf)
                .withPriority(priority)
                .makeTemporary(FLOW_TIMEOUT)
                .build();

        // Apply all flow rules for forward and reverse paths
        flowRuleService.applyFlowRules(forwardFlowRuleSrcLeaf, forwardFlowRuleSpine, forwardFlowRuleDstLeaf,
                reverseFlowRuleDstLeaf, reverseFlowRuleSpine, reverseFlowRuleSrcLeaf);

        // Send the initial packet on the forward path
        context.treatmentBuilder().setOutput(srcLeafUplink);
        context.send();
    }

    private PortNumber getConnectingPort(DeviceId a, DeviceId b) {
        Iterable<Link> links = linkService.getLinks();

        for (Link link : links) {
            DeviceId src = link.src().deviceId();
            DeviceId dst = link.dst().deviceId();

            if (src.equals(a) && dst.equals(b)) {
                return link.src().port();
            }
        }
        return null;
    }

    private PortNumber getHostFacingPort(DeviceId leafId, IpAddress hostIp) {
        return hostService.getHostsByIp(hostIp).stream()
                .filter(host -> host.location().deviceId().equals(leafId))
                .map(host -> host.location().port())
                .findFirst()
                .orElse(null);
    }

    private boolean isEligibleForOpticalPath(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();

        // Check if it's an IPv4 packet
        if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) return false;

        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();

        // Check if it's a TCP packet
        if (ipv4Pkt.getProtocol() != IPv4.PROTOCOL_TCP) return false;

        TCP tcpPkt = (TCP) ipv4Pkt.getPayload();

        // Check if its iPerf traffic (5001/TCP)
        return tcpPkt.getDestinationPort() == 5001;
    }

    private boolean isOpticalPathAvailable(DeviceId srcLeaf, DeviceId dstLeaf) {
        log.info("Checking optical path availability: srcLeaf={}, dstLeaf={}", srcLeaf, dstLeaf);

        // Get the connecting ports
        PortNumber spineToSrcPort = getConnectingPort(SPINE_OPTICAL, srcLeaf);
        PortNumber spineToDstPort = getConnectingPort(SPINE_OPTICAL, dstLeaf);

        // Ensure all ports are identified
        if (spineToSrcPort == null || spineToDstPort == null) return false;

        // Check if these ports are already in use by any existing flows
        Iterable<FlowEntry> flows = flowRuleService.getFlowEntries(SPINE_OPTICAL);

        for (FlowEntry flow : flows) {
            TrafficTreatment treatment = flow.treatment();

            for (Instruction instruction : treatment.allInstructions()) {
                if (instruction instanceof Instructions.OutputInstruction) {
                    PortNumber outputPort = ((Instructions.OutputInstruction) instruction).port();

                    // Check if the port is already in use
                    if (outputPort.equals(spineToSrcPort) || outputPort.equals(spineToDstPort)) {
                        log.warn("Port is already in use by another flow. Path is not available.");
                        return false;
                    }
                }
            }
        }

        // If no conflicting ports are found, the path is available
        log.info("Optical path is available.");
        return true;
    }
}
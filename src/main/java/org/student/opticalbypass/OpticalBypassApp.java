package org.student.opticalbypass;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.TrafficSelector.Builder;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.*;
import org.osgi.service.component.annotations.*;

import java.util.stream.StreamSupport;

@Component(immediate = true)
public class OpticalBypassApp {
    private final PacketProcessor packetProcessor = new OpticalBypassPacketProcessor();
    private ApplicationId appId;
    private DeviceId SPINE_ELECTRICAL;
    private DeviceId SPINE_OPTICAL;

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

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.student.opticalbypass");
        
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
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flowRuleService.removeFlowRulesById(appId);
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

            if (srcHost == null || dstHost == null) return;

            // Get source and destination leaf(s)
            DeviceId srcLeaf = srcHost.location().deviceId();
            DeviceId dstLeaf = dstHost.location().deviceId();

            if (srcLeaf.equals(dstLeaf)) {
                handleIntraLeafTraffic(context, srcHost, dstHost);
            } else {
                handleInterLeafTraffic(context, srcLeaf, dstLeaf);
            }
        }

        private void handleIntraLeafTraffic(PacketContext context, Host srcHost, Host dstHost) {
            int PRIORITY_LOCAL = 30;
            
            // Match any flow between hosts - mirrors org.onosproject.fwd logic
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchInPort(srcHost.location().port())
                    .matchEthSrc(srcHost.mac())
                    .matchEthDst(dstHost.mac())
                    .build();
            TrafficTreatment treatment = createTreatment(dstHost.location().port());
            FlowRule flowRule = createFlowRule(srcHost.location().deviceId(), selector, treatment, PRIORITY_LOCAL);
        
            flowRuleService.applyFlowRules(flowRule);
            context.treatmentBuilder().setOutput(dstHost.location().port());
            context.send();
        }        

        private void handleInterLeafTraffic(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf) {
            if (isEligibleForOpticalPath(context) && isOpticalPathAvailable(srcLeaf, dstLeaf)) {
                routeViaSpine(context, srcLeaf, dstLeaf, SPINE_OPTICAL, 20);
            } else {
                routeViaSpine(context, srcLeaf, dstLeaf, SPINE_ELECTRICAL, 10);
            }
        }

        private void routeViaSpine(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf, DeviceId spineDeviceId, int priority) {
            Ethernet ethPkt = context.inPacket().parsed();
            IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
        
            PortNumber srcLeafUplink = getConnectingPort(srcLeaf, spineDeviceId);
            PortNumber spineToDestPort = getConnectingPort(spineDeviceId, dstLeaf);
            PortNumber dstLeafDownlink = getHostFacingPort(dstLeaf, IpAddress.valueOf(ipv4Pkt.getDestinationAddress()));
        
            PortNumber dstLeafUplink = getConnectingPort(dstLeaf, spineDeviceId);
            PortNumber spineToSrcPort = getConnectingPort(spineDeviceId, srcLeaf);
            PortNumber srcLeafDownlink = getHostFacingPort(srcLeaf, IpAddress.valueOf(ipv4Pkt.getSourceAddress()));
        
            TrafficSelector forwardSelector = createTrafficSelector(ethPkt, ipv4Pkt, true);
            TrafficSelector reverseSelector = createTrafficSelector(ethPkt, ipv4Pkt, false);
        
            // Create flow rules using helpers
            FlowRule forwardFlowRuleSrcLeaf = createFlowRule(srcLeaf, forwardSelector, createTreatment(srcLeafUplink), priority);
            FlowRule forwardFlowRuleSpine = createFlowRule(spineDeviceId, forwardSelector, createTreatment(spineToDestPort), priority);
            FlowRule forwardFlowRuleDstLeaf = createFlowRule(dstLeaf, forwardSelector, createTreatment(dstLeafDownlink), priority);
        
            FlowRule reverseFlowRuleDstLeaf = createFlowRule(dstLeaf, reverseSelector, createTreatment(dstLeafUplink), priority);
            FlowRule reverseFlowRuleSpine = createFlowRule(spineDeviceId, reverseSelector, createTreatment(spineToSrcPort), priority);
            FlowRule reverseFlowRuleSrcLeaf = createFlowRule(srcLeaf, reverseSelector, createTreatment(srcLeafDownlink), priority);
        
            // Apply all flow rules
            flowRuleService.applyFlowRules(forwardFlowRuleSrcLeaf, forwardFlowRuleSpine, forwardFlowRuleDstLeaf,
                                           reverseFlowRuleDstLeaf, reverseFlowRuleSpine, reverseFlowRuleSrcLeaf);
        
            // Send the packet
            context.treatmentBuilder().setOutput(srcLeafUplink);
            context.send();
        }
    
        private TrafficTreatment createTreatment(PortNumber outputPort) {
            return DefaultTrafficTreatment.builder()
                    .setOutput(outputPort)
                    .build();
        }
    
        private FlowRule createFlowRule(DeviceId deviceId, TrafficSelector selector, TrafficTreatment treatment, int priority) {
            return DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withPriority(priority)
                    .fromApp(appId)
                    .makeTemporary(20)
                    .build();
        }

        private TrafficSelector createTrafficSelector(Ethernet ethPkt, IPv4 ipv4Pkt, boolean isForward) {
            MacAddress srcMac = isForward ? ethPkt.getSourceMAC() : ethPkt.getDestinationMAC();
            MacAddress dstMac = isForward ? ethPkt.getDestinationMAC() : ethPkt.getSourceMAC();
            IpAddress srcIp = isForward ? IpAddress.valueOf(ipv4Pkt.getSourceAddress()) : IpAddress.valueOf(ipv4Pkt.getDestinationAddress());
            IpAddress dstIp = isForward ? IpAddress.valueOf(ipv4Pkt.getDestinationAddress()) : IpAddress.valueOf(ipv4Pkt.getSourceAddress());
        
            Builder selectorBuilder = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchEthSrc(srcMac)
                    .matchEthDst(dstMac)
                    .matchIPSrc(IpPrefix.valueOf(srcIp, 32))
                    .matchIPDst(IpPrefix.valueOf(dstIp, 32))
                    .matchIPProtocol(ipv4Pkt.getProtocol());
        
            if (ipv4Pkt.getProtocol() == IPv4.PROTOCOL_TCP) {
                TCP tcpPkt = (TCP) ipv4Pkt.getPayload();
                selectorBuilder.matchTcpSrc(TpPort.tpPort(isForward ? tcpPkt.getSourcePort() : tcpPkt.getDestinationPort()))
                               .matchTcpDst(TpPort.tpPort(isForward ? tcpPkt.getDestinationPort() : tcpPkt.getSourcePort()));
            }
            return selectorBuilder.build();
        }
            
        private PortNumber getConnectingPort(DeviceId srcDeviceId, DeviceId dstDeviceId) {
            return linkService.getDeviceLinks(srcDeviceId).stream()
                    .filter(link -> link.dst().deviceId().equals(dstDeviceId))
                    .map(link -> link.src().port())
                    .findFirst()
                    .orElse(null); // Return null if no matches
        }
    
        private PortNumber getHostFacingPort(DeviceId leafId, IpAddress hostIp) {
            return hostService.getHostsByIp(hostIp).stream()
                    .filter(host -> host.location().deviceId().equals(leafId))
                    .map(host -> host.location().port())
                    .findFirst()
                    .orElse(null); // Return null if no matches
        }
    
        private boolean isEligibleForOpticalPath(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
    
            // Check if it's a TCP packet
            if (ipv4Pkt.getProtocol() != IPv4.PROTOCOL_TCP) return false;
    
            TCP tcpPkt = (TCP) ipv4Pkt.getPayload();
    
            // Check if its iPerf traffic (5001/TCP)
            return tcpPkt.getDestinationPort() == 5001;
        }
    
        private boolean isOpticalPathAvailable(DeviceId srcLeaf, DeviceId dstLeaf) {
            // Get the ports connecting the optical spine to the leaves
            PortNumber spineToSrcPort = getConnectingPort(SPINE_OPTICAL, srcLeaf);
            PortNumber spineToDstPort = getConnectingPort(SPINE_OPTICAL, dstLeaf);
    
            if (spineToSrcPort == null || spineToDstPort == null) {
                return false; // Path doesn't exist
            }
    
            // Check if these ports are used in existing flows
            return StreamSupport.stream(flowRuleService.getFlowEntries(SPINE_OPTICAL).spliterator(), false)
                    .flatMap(flow -> flow.treatment().allInstructions().stream())
                    .filter(instruction -> instruction instanceof Instructions.OutputInstruction)
                    .map(instruction -> ((Instructions.OutputInstruction) instruction).port())
                    .noneMatch(port -> port.equals(spineToSrcPort) || port.equals(spineToDstPort));
        }    
    }
}
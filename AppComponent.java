package org.student.opticalbypass;

import javafx.util.Pair;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import java.util.*;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
public class AppComponent {
    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    private static final int FLOW_TIMEOUT = 30;
    private static final int PRIORITY_ELECTRICAL = 20000;
    private static final int PRIORITY_OPTICAL = 10000;
    private static final DeviceId SPINE_ELECTRICAL = DeviceId.deviceId("of:0000000000000005");
    private static final DeviceId SPINE_OPTICAL = DeviceId.deviceId("of:0000000000000006");
    private final ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;
    private final InternalHostListener hostListener = new InternalHostListener();
    private final ArrayList<TrafficSelector> aclRules = new ArrayList<>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.student.opticalbypass");
        packetService.addProcessor(processor, PacketProcessor.director(1));
        hostService.addListener(hostListener);
        defineAclRules();
        log.info("Started {}", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        hostService.removeListener(hostListener);
        log.info("Stopped {}", appId.id());
    }

    public void defineAclRules() {
        // Add ACL rules for iPerf traffic
        aclRules.add(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchTcpDst(TpPort.tpPort(5001))
                .build());
        aclRules.add(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchTcpSrc(TpPort.tpPort(5001))
                .build());
        /*
         * // Add ACL rules for ICMP traffic
         * aclRules.add(DefaultTrafficSelector.builder()
         * .matchEthType(Ethernet.TYPE_IPV4)
         * .matchIPProtocol(IPv4.PROTOCOL_ICMP)
         * .build());
         */
    }

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled())
                return;

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null)
                return;

            // Get source and destination hosts
            Host srcHost = hostService.getHost(HostId.hostId(ethPkt.getSourceMAC()));
            Host dstHost = hostService.getHost(HostId.hostId(ethPkt.getDestinationMAC()));

            if (srcHost == null || dstHost == null) {
                return;
            }

            DeviceId srcLeaf = srcHost.location().deviceId();
            DeviceId dstLeaf = dstHost.location().deviceId();

            // If hosts are on the same leaf, no need to process further
            if (srcLeaf.equals(dstLeaf)) {
                handleIntraLeafTraffic(context, srcHost, dstHost);
                return;
            }

            handleInterLeafTraffic(context, srcLeaf, dstLeaf);
        }
    }

    private void handleIntraLeafTraffic(PacketContext context, Host srcHost, Host dstHost) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthSrc(srcHost.mac())
                .matchEthDst(dstHost.mac())
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(dstHost.location().port())
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(srcHost.location().deviceId())
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(40000)
                .makeTemporary(FLOW_TIMEOUT)
                .build();

        flowRuleService.applyFlowRules(flowRule);
        context.treatmentBuilder().setOutput(dstHost.location().port());
        context.send();
    }

    private void handleInterLeafTraffic(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf) {
        if (isEligibleForOpticalPath(context) && isOpticalPathAvailable(srcLeaf, dstLeaf)) {
            routeViaOptical(context, srcLeaf, dstLeaf);
        } else {
            routeViaElectrical(context, srcLeaf, dstLeaf);
        }
    }

    private void routeViaOptical(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
        TCP tcpPkt = (TCP) ipv4Pkt.getPayload();

        // Get the ports in the circuit
        PortNumber srcLeafUplink = getConnectingPort(srcLeaf, SPINE_OPTICAL);
        PortNumber spineToDestPort = getConnectingPort(SPINE_OPTICAL, dstLeaf);
        PortNumber dstLeafDownlink = getHostFacingPort(dstLeaf, IpAddress.valueOf(ipv4Pkt.getDestinationAddress()));

        if (srcLeafUplink == null || spineToDestPort == null || dstLeafDownlink == null) {
            log.error("Unable to find required ports for path");
            return;
        }

        // Create a selector to match against rules
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchTcpDst(TpPort.tpPort(tcpPkt.getDestinationPort()))
                .build();

        // Create port-based treatments
        TrafficTreatment treatmentSrcLeaf = DefaultTrafficTreatment.builder()
                .setOutput(srcLeafUplink)
                .build();
        TrafficTreatment treatmentSpine = DefaultTrafficTreatment.builder()
                .setOutput(spineToDestPort)
                .build();
        TrafficTreatment treatmentDstLeaf = DefaultTrafficTreatment.builder()
                .setOutput(dstLeafDownlink)
                .build();

        // Create flow rules
        FlowRule flowRuleSrcLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(srcLeaf)
                .withSelector(selector)
                .withTreatment(treatmentSrcLeaf)
                .withPriority(PRIORITY_OPTICAL)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule flowRuleSpine = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(SPINE_OPTICAL)
                .withSelector(selector)
                .withTreatment(treatmentSpine)
                .withPriority(PRIORITY_OPTICAL)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule flowRuleDstLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(dstLeaf)
                .withSelector(selector)
                .withTreatment(treatmentDstLeaf)
                .withPriority(PRIORITY_OPTICAL)
                .makeTemporary(FLOW_TIMEOUT)
                .build();

        // Apply all flow rules
        flowRuleService.applyFlowRules(flowRuleSrcLeaf, flowRuleSpine, flowRuleDstLeaf);
        context.send();

    }

    private void routeViaElectrical(PacketContext context, DeviceId srcLeaf, DeviceId dstLeaf) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();

        // Get the ports in the circuit
        PortNumber srcLeafUplink = getConnectingPort(srcLeaf, SPINE_ELECTRICAL);
        PortNumber spineToDestPort = getConnectingPort(SPINE_ELECTRICAL, dstLeaf);
        PortNumber dstLeafDownlink = getHostFacingPort(dstLeaf, IpAddress.valueOf(ipv4Pkt.getDestinationAddress()));

        if (srcLeafUplink == null || spineToDestPort == null || dstLeafDownlink == null) {
            log.error("Unable to find required ports for path");
            return;
        }

        // Create traffic selector
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getSourceAddress()), 32))
                .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(ipv4Pkt.getDestinationAddress()), 32))
                .build();

        // Create port-based treatments
        TrafficTreatment treatmentSrcLeaf = DefaultTrafficTreatment.builder()
                .setOutput(srcLeafUplink)
                .build();
        TrafficTreatment treatmentSpine = DefaultTrafficTreatment.builder()
                .setOutput(spineToDestPort)
                .build();
        TrafficTreatment treatmentDstLeaf = DefaultTrafficTreatment.builder()
                .setOutput(dstLeafDownlink)
                .build();

        // Create flow rules
        FlowRule flowRuleSrcLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(srcLeaf)
                .withSelector(selector)
                .withTreatment(treatmentSrcLeaf)
                .withPriority(PRIORITY_ELECTRICAL)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule flowRuleSpine = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(SPINE_ELECTRICAL)
                .withSelector(selector)
                .withTreatment(treatmentSpine)
                .withPriority(PRIORITY_ELECTRICAL)
                .makeTemporary(FLOW_TIMEOUT)
                .build();
        FlowRule flowRuleDstLeaf = DefaultFlowRule.builder()
                .fromApp(appId)
                .forDevice(dstLeaf)
                .withSelector(selector)
                .withTreatment(treatmentDstLeaf)
                .withPriority(PRIORITY_ELECTRICAL)
                .makeTemporary(FLOW_TIMEOUT)
                .build();

        // Apply all flow rules
        flowRuleService.applyFlowRules(flowRuleSrcLeaf, flowRuleSpine, flowRuleDstLeaf);
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
        if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
            return false;
        }

        IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();

        // Check if it's a TCP packet
        if (ipv4Pkt.getProtocol() != IPv4.PROTOCOL_TCP) {
            return false;
        }

        TCP tcpPkt = (TCP) ipv4Pkt.getPayload();

        // Create a selector to match against rules
        TrafficSelector trafficSelector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchTcpDst(TpPort.tpPort(tcpPkt.getDestinationPort()))
                .build();

        // Check if the packet matches any of our ACL rules
        return aclRules.stream().anyMatch(rule -> matches(trafficSelector, rule));
    }

    private boolean matches(TrafficSelector selector, TrafficSelector rule) {
        // Get all criteria from the rule
        for (Criterion ruleCriterion : rule.criteria()) {
            // Find the corresponding criterion in the selector
            Criterion selectorCriterion = selector.getCriterion(ruleCriterion.type());

            // If the selector doesn't have this criterion or it doesn't match, return false
            if (selectorCriterion == null || !selectorCriterion.equals(ruleCriterion)) {
                return false;
            }
        }
        return true;
        /*
         * return rule.criteria().stream().anyMatch(ruleCriterion -> {
         * Criterion selectorCriterion = selector.getCriterion(ruleCriterion.type());
         * 
         * // If the selector doesn't have this criterion or it doesn't match, return
         * false
         * return selectorCriterion != null && selectorCriterion.equals(ruleCriterion);
         * });
         */
    }

    private boolean isOpticalPathAvailable(DeviceId srcLeaf, DeviceId dstLeaf) {
        // TODO: Implement
        return true;
    }

    private class InternalHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            Host host = event.subject();
            log.info("Host event: {}", host);
        }
    }
}
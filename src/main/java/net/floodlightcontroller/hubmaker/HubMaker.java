package net.floodlightcontroller.hubmaker;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;

import java.util.*;

// paag: with IControllerCompletionListener that logswhen an input event has been consumed
public class HubMaker implements IFloodlightModule, IOFMessageListener {

	// Module dependencies
	protected IFloodlightProviderService floodlightProviderService;

	private enum HubType {
		USE_PACKET_OUT, USE_FLOW_MOD
	};

	/**
	 * @param floodlightProvider the floodlightProvider to set
	 */
	public void setFloodlightProvider(IFloodlightProviderService floodlightProviderService) {
		this.floodlightProviderService = floodlightProviderService;
	}

	@Override
	public String getName() {
		return "Hub Maker";
	}

	private OFMessage createHubFlowMod(IOFSwitch sw, OFMessage msg) {
		OFPacketIn pi = (OFPacketIn) msg;
		OFFlowAdd.Builder fmb = sw.getOFFactory().buildFlowAdd();
		fmb.setBufferId(pi.getBufferId()).setXid(pi.getXid());
		// set actions
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		actionBuilder.setPort(OFPort.FLOOD);
		// import java.util.Collections
		fmb.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		return fmb.build();
	}

	private OFMessage createHubPacketOut(IOFSwitch sw, OFMessage msg) {
		OFPacketIn pi = (OFPacketIn) msg;
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

		pob.setBufferId(pi.getBufferId()).setXid(pi.getXid())
				.setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
						: pi.getMatch().get(MatchField.IN_PORT)));

		// set actions
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		if (sw.getId().getLong() == 1) {
			int port = pob.getInPort().getPortNumber();
			OFActionOutput.Builder actionBuilder2 = sw.getOFFactory().actions().buildOutput();
			List<OFAction> list = new ArrayList<>();
			switch (port) {
				case 1:
					list.add((OFAction) actionBuilder.setPort(OFPort.of(3)).build());
					break;
				case 3:
					list.add((OFAction) actionBuilder.setPort(OFPort.of(1)).build());
					break;
				default:
				case 2:
					list.add((OFAction) actionBuilder.setPort(OFPort.of(1)).build());
					list.add((OFAction) actionBuilder2.setPort(OFPort.of(3)).build());
					break;
			}
			pob.setActions(list);
		} else {
			actionBuilder.setPort(OFPort.FLOOD);
			pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		}
		// set data if it is included in the packetin
		if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
			byte[] packetData = pi.getData();
			pob.setData(packetData);
		}
		return pob.build();
	}
	// IOFMessageListener

	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		OFMessage outMessage;
		HubType ht = HubType.USE_PACKET_OUT;
		if (sw.getId().getLong() == 1) {
			OFPacketIn pi = (OFPacketIn) msg;
			OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
					: pi.getMatch().get(MatchField.IN_PORT));
			if (inPort.getPortNumber() == 2) {
				return Command.CONTINUE;
			}
		}

		switch (ht) {
			case USE_FLOW_MOD:
				outMessage = createHubFlowMod(sw, msg);
				break;
			default:
			case USE_PACKET_OUT:
				outMessage = createHubPacketOut(sw, msg);
				break;
		}
		sw.write(outMessage);
		return Command.CONTINUE;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	// IFloodlightModule

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
	}
}

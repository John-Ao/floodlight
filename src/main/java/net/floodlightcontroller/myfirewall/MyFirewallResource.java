package net.floodlightcontroller.myfirewall;

import java.io.IOException;
import java.util.List;
import java.util.Collections;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.restlet.resource.Delete;
import org.restlet.resource.Post;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyFirewallResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(MyFirewallResource.class);

	@Get("json")
	public List<FirewallRule> list() {
		return MyFirewall.rules;
	}

	private void solvePriorityConflict(int p, List<FirewallRule> list) {
		Collections.sort(list);
		boolean found = false;
		int i, j;
		for (i = 0, j = list.size(); i < j; ++i) {
			if (list.get(i).priority == p) {
				found = true;
				break;
			}
		}
		if (found) { // solve priority conflicts
			for (; i < j; ++i) {
				FirewallRule r = list.get(i);
				if (r.priority == p || r.priority == ++p) {
					r.priority = p + 1;
					log.info("Rule " + r.ruleid + " priority " + p + " -> " + (p + 1));
					list.set(i, r);
				} else {
					break;
				}
			}
		}
	}

	@Post
	public String add(String fmJson) {
		FirewallRule rule = jsonToFirewallRule(fmJson);
		if (rule == null) {
			return "{\"code\":0, \"status\" : \"Error! Could not parse firewall rule, see log for details.\"}\n";
		}
		String status = null;
		synchronized (MyFirewall.rules) {
			if (checkRuleExists(rule, MyFirewall.rules)) {
				status = "Error! A similar firewall rule already exists.";
				log.error(status);
				return ("{\"code\":0, \"status\" : \"" + status + "\"}\n");
			} else {
				if (rule.ruleid != -1) {
					boolean found = false;
					int i, j;
					int id = rule.ruleid;
					for (i = 0, j = MyFirewall.rules.size(); i < j; ++i) {
						if (MyFirewall.rules.get(i).ruleid == id) {
							found = true;
							break;
						}
					}
					if (found) {
						int p = rule.priority;
						rule.priority = -1;
						MyFirewall.rules.set(i, rule);
						solvePriorityConflict(p, MyFirewall.rules);
						Collections.sort(MyFirewall.rules);
						rule.priority = p;
						MyFirewall.rules.set(0, rule);
						Collections.sort(MyFirewall.rules);
						status = "Rule " + Integer.toString(rule.ruleid) + " editted";
						log.info(status);
						return ("{\"code\":1, \"status\" : \"" + status + "\"}\n");
					}
				} else {
					rule.ruleid = MyFirewall.rule_id++;
				}
				solvePriorityConflict(rule.priority, MyFirewall.rules);
				MyFirewall.rules.add(rule);
				Collections.sort(MyFirewall.rules);
				return ("{\"code\":1, \"status\" : \"Rule added\", \"rule-id\" : \"" + Integer.toString(rule.ruleid)
						+ "\"}\n");
			}
		}
	}

	@Delete
	public String remove(String fmJson) {
		FirewallRule rule = jsonToFirewallRule(fmJson);
		if (rule == null) {
			return "{\"code\":0, \"status\" : \"Error! Could not parse firewall rule, see log for details.\"}\n";
		}

		String status = null;
		boolean exists = false;
		int i, j;
		for (i = 0, j = MyFirewall.rules.size(); i < j; ++i) {
			if (MyFirewall.rules.get(i).ruleid == rule.ruleid) {
				exists = true;
				break;
			}
		}
		int code = 0;
		if (!exists) {
			status = "Error! Can't delete, a rule with this ID doesn't exist.";
			log.error(status);
		} else {
			MyFirewall.rules.remove(i);
			status = "Rule deleted";
			code = 1;
		}
		return ("{\"code\":" + code + ", \"status\" : \"" + status + "\"}\n");
	}

	public static FirewallRule jsonToFirewallRule(String fmJson) {
		log.info(fmJson);
		FirewallRule rule = new FirewallRule();
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;
		rule.ruleid = -1;
		try {
			try {
				jp = f.createParser(fmJson);
			} catch (JsonParseException e) {
				throw new IOException(e);
			}

			jp.nextToken();
			if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
				throw new IOException("Expected START_OBJECT");
			}

			while (jp.nextToken() != JsonToken.END_OBJECT) {
				if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
					throw new IOException("Expected FIELD_NAME");
				}

				String n = jp.getCurrentName();
				jp.nextToken();
				if (jp.getText().equals("")) {
					continue;
				}

				// This is currently only applicable for remove(). In store(), ruleid takes a
				// random number
				if (n.equalsIgnoreCase("ruleid")) {
					try {
						rule.ruleid = Integer.parseInt(jp.getText());
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse rule ID: {}", jp.getText());
					}
				} else if (n.equalsIgnoreCase("switchid")) {
					rule.any_dpid = false;
					try {
						rule.dpid = DatapathId.of(jp.getText());
					} catch (NumberFormatException e) {
						log.error("Unable to parse switch DPID: {}", jp.getText());
					}
				} else if (n.equalsIgnoreCase("src-inport")) {
					rule.any_in_port = false;
					try {
						rule.in_port = OFPort.of(Integer.parseInt(jp.getText()));
					} catch (NumberFormatException e) {
						log.error("Unable to parse ingress port: {}", jp.getText());
					}
				} else if (n.equalsIgnoreCase("src-mac")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_dl_src = false;
						try {
							rule.dl_src = MacAddress.of(jp.getText());
						} catch (IllegalArgumentException e) {
							log.error("Unable to parse source MAC: {}", jp.getText());
						}
					}
				} else if (n.equalsIgnoreCase("dst-mac")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_dl_dst = false;
						try {
							rule.dl_dst = MacAddress.of(jp.getText());
						} catch (IllegalArgumentException e) {
							log.error("Unable to parse destination MAC: {}", jp.getText());
						}
					}
				} else if (n.equalsIgnoreCase("proto")) {
					if (jp.getText().equalsIgnoreCase("ARP")) {
						rule.any_dl_type = false;
						rule.dl_type = EthType.ARP;
					} else if (jp.getText().equalsIgnoreCase("TCP")) {
						rule.any_nw_proto = false;
						rule.nw_proto = IpProtocol.TCP;
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					} else if (jp.getText().equalsIgnoreCase("UDP")) {
						rule.any_nw_proto = false;
						rule.nw_proto = IpProtocol.UDP;
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					} else if (jp.getText().equalsIgnoreCase("ICMP")) {
						rule.any_nw_proto = false;
						rule.nw_proto = IpProtocol.ICMP;
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					}
				} else if (n.equalsIgnoreCase("src-ip")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_nw_src = false;
						if (rule.dl_type.equals(EthType.NONE)) {
							rule.any_dl_type = false;
							rule.dl_type = EthType.IPv4;
						}
						try {
							rule.nw_src = IPv4Address.of(jp.getText());
						} catch (IllegalArgumentException e) {
							log.error("Unable to parse source IP: {}", jp.getText());
						}
					}
				} else if (n.equalsIgnoreCase("dst-ip")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_nw_dst = false;
						if (rule.dl_type.equals(EthType.NONE)) {
							rule.any_dl_type = false;
							rule.dl_type = EthType.IPv4;
						}
						try {
							rule.nw_dst = IPv4Address.of(jp.getText());
						} catch (IllegalArgumentException e) {
							log.error("Unable to parse destination IP: {}", jp.getText());
						}
					}
				} else if (n.equalsIgnoreCase("tp-src")) {
					rule.any_tp_src = false;
					try {
						rule.tp_src = TransportPort.of(Integer.parseInt(jp.getText()));
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse source transport port: {}", jp.getText());
					}
				} else if (n.equalsIgnoreCase("tp-dst")) {
					rule.any_tp_dst = false;
					try {
						rule.tp_dst = TransportPort.of(Integer.parseInt(jp.getText()));
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse destination transport port: {}", jp.getText());
					}
				} else if (n.equalsIgnoreCase("priority")) {
					try {
						rule.priority = Integer.parseInt(jp.getText());
					} catch (IllegalArgumentException e) {
						log.error("Unable to parse priority: {}", jp.getText());
					}
				} else if (n.equalsIgnoreCase("action")) {
					if (jp.getText().equalsIgnoreCase("allow") || jp.getText().equalsIgnoreCase("accept")) {
						rule.action = FirewallRule.FirewallAction.ALLOW;
					} else if (jp.getText().equalsIgnoreCase("deny") || jp.getText().equalsIgnoreCase("drop")) {
						rule.action = FirewallRule.FirewallAction.DROP;
					}
				}
			}
		} catch (IOException e) {
			log.error("Unable to parse JSON string: {}", e);
		}
		return rule;
	}

	public static boolean checkRuleExists(FirewallRule rule, List<FirewallRule> rules) {
		for (FirewallRule r : rules) {
			if (rule.isSameAs(r)) {
				log.info("Same with rule " + r.ruleid);
				if (rule.ruleid == r.ruleid && rule.priority != r.priority) {
					return false;
				} else {
					return true;
				}
			}
		}
		return false;
	}
}

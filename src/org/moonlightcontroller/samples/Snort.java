package org.moonlightcontroller.samples;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import org.moonlightcontroller.bal.BoxApplication;
import org.moonlightcontroller.blocks.Discard;
import org.moonlightcontroller.blocks.FromDevice;
import org.moonlightcontroller.blocks.FromDump;
import org.moonlightcontroller.blocks.HeaderClassifier;
import org.moonlightcontroller.blocks.HeaderClassifier.HeaderClassifierRule;
import org.moonlightcontroller.blocks.RegexClassifier;
import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.blocks.ToDump;
// import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.events.IHandleClient;
import org.moonlightcontroller.events.IInstanceUpListener;
import org.moonlightcontroller.events.InstanceUpArgs;
import org.moonlightcontroller.processing.Connector;
import org.moonlightcontroller.processing.IConnector;
import org.moonlightcontroller.processing.IProcessingBlock;
import org.moonlightcontroller.processing.ProcessingGraph;
import org.openboxprotocol.protocol.HeaderField;
import org.openboxprotocol.protocol.HeaderMatch;
import org.openboxprotocol.protocol.IStatement;
import org.openboxprotocol.protocol.OpenBoxHeaderMatch;
import org.openboxprotocol.protocol.Priority;
import org.openboxprotocol.protocol.Statement;
import org.moonlightcontroller.topology.IApplicationTopology;
import org.moonlightcontroller.topology.TopologyManager;
import org.openboxprotocol.types.TransportPort;

import com.google.common.collect.ImmutableList;

public class Snort extends BoxApplication{

	private final static Logger LOG = Logger.getLogger(Snort.class.getName());
	
	public static final String PROPERTIES_PATH = "Snort.properties";

	public static final String PROP_SEGMENT = "segment";
	public static final String PROP_IN_IFC = "in_ifc";
	public static final String PROP_OUT_IFC = "out_ifc";
	public static final String PROP_IN_DUMP = "in_dump";
	public static final String PROP_OUT_DUMP = "out_dump";
	public static final String PROP_IN_USE_IFC = "in_use_ifc";
	public static final String PROP_OUT_USE_IFC = "out_use_ifc";
	public static final String PROP_ALERT = "alert";
	public static final String PROP_RULE_FILE = "rule_file";
	
	public static final String DEFAULT_SEGMENT = "220";
	public static final String DEFAULT_IN_IFC = "eth0";
	public static final String DEFAULT_OUT_IFC = "eth0";
	public static final String DEFAULT_IN_DUMP = "in_dump.pcap";
	public static final String DEFAULT_OUT_DUMP = "out_dump.pcap";
	public static final String DEFAULT_IN_USE_IFC = "true";
	public static final String DEFAULT_OUT_USE_IFC = "true";
	public static final String DEFAULT_ALERT = "true";
	public static final String DEFAULT_RULE_FILE = "snort_rules.txt";
	
	private static final Properties DEFAULT_PROPS = new Properties();
	
	static {
		DEFAULT_PROPS.setProperty(PROP_SEGMENT, DEFAULT_SEGMENT);
		DEFAULT_PROPS.setProperty(PROP_IN_IFC, DEFAULT_IN_IFC);
		DEFAULT_PROPS.setProperty(PROP_OUT_IFC, DEFAULT_OUT_IFC);
		DEFAULT_PROPS.setProperty(PROP_IN_DUMP, DEFAULT_IN_DUMP);
		DEFAULT_PROPS.setProperty(PROP_OUT_DUMP, DEFAULT_OUT_DUMP);
		DEFAULT_PROPS.setProperty(PROP_IN_USE_IFC, DEFAULT_IN_USE_IFC);
		DEFAULT_PROPS.setProperty(PROP_OUT_USE_IFC, DEFAULT_OUT_USE_IFC);
		DEFAULT_PROPS.setProperty(PROP_ALERT, DEFAULT_ALERT);
		DEFAULT_PROPS.setProperty(PROP_RULE_FILE, DEFAULT_RULE_FILE);
	}
	
	private Properties props;
	
	public Snort() {
		super("Snort");
		
		props = new Properties(DEFAULT_PROPS);
		File f = new File(PROPERTIES_PATH);
		try {
			props.load(new FileReader(f));
		} catch (IOException e) {
			LOG.severe("Cannot load properties file from path: " + f.getAbsolutePath());
			LOG.severe("Using default properties.");
		}
		LOG.info(String.format("Snort is running on Segment %s", props.getProperty(PROP_SEGMENT)));
		LOG.info(String.format("[->] Input: %s", (Boolean.parseBoolean(props.getProperty(PROP_IN_USE_IFC)) ? props.getProperty(PROP_IN_IFC) : props.getProperty(PROP_IN_DUMP))));
		LOG.info(String.format("[<-] Output: %s", (Boolean.parseBoolean(props.getProperty(PROP_OUT_USE_IFC)) ? props.getProperty(PROP_OUT_IFC) : props.getProperty(PROP_OUT_DUMP))));
		LOG.info(String.format("[!!] Alert is %s", (Boolean.parseBoolean(props.getProperty(PROP_ALERT)) ? "on" : "off")));
		LOG.info(String.format("[>|] Rule files path: %s", props.getProperty(PROP_RULE_FILE)));
		
		this.setStatements(createStatements());
		this.setInstanceUpListener(new InstanceUpHandler());
	}
	
	@Override
	public void handleAppStart(IApplicationTopology top, IHandleClient handles) {
		LOG.info("Got App Start Event");
	}

	private List<String> readRules(String path) {
		List<String> result = new ArrayList<>();
		
		File f = new File(path);
		
		BufferedReader reader = null;
		String line;
		try {
			reader = new BufferedReader(new FileReader(f));
			while ((line = reader.readLine()) != null) {
				result.add(line);
			}
		} catch (IOException e) {
			LOG.severe("Error (" + e.getClass().getName() + ") while reading rules from file: " + e.getMessage());
		} finally {
			if (reader != null) {
				try { reader.close(); } catch (Exception e) { }
			}
		}
		result.add(".*"); // Default rule
		
		return result;
	}
	
	private List<IStatement> createStatements() {
		
		HeaderMatch h1 = new OpenBoxHeaderMatch.Builder().setExact(HeaderField.TCP_SRC, new TransportPort(80)).build();
		HeaderMatch h2 = new OpenBoxHeaderMatch.Builder().build();
		
		List<HeaderClassifierRule> headerRules = Arrays.asList(
				new HeaderClassifierRule.Builder().setHeaderMatch(h1).setPriority(Priority.HIGH).setOrder(0).build(),
				new HeaderClassifierRule.Builder().setHeaderMatch(h2).setPriority(Priority.MEDIUM).setOrder(1).build());

		List<String> regexRules = readRules(props.getProperty(PROP_RULE_FILE));
				
		FromDevice fromDevice = new FromDevice("FromDevice_Snort", props.getProperty(PROP_IN_IFC), true, true);
		ToDevice toDevice = new ToDevice("ToDevice_Snort", props.getProperty(PROP_OUT_IFC));
		FromDump fromDump = new FromDump("FromDump_Snort", props.getProperty(PROP_IN_DUMP), false, true);
		ToDump toDump = new ToDump("ToDump_Snort", props.getProperty(PROP_OUT_DUMP));
		HeaderClassifier classify = new HeaderClassifier("HeaderClassifier_Snort", headerRules, Priority.HIGH, true);
		RegexClassifier regex = new RegexClassifier("RegexClassifier_Snort", regexRules, Priority.HIGH);
		org.moonlightcontroller.blocks.Alert alert = 
				new org.moonlightcontroller.blocks.Alert("Alert_Snort", "Alert from Snort", 1, true, 1000);
		Discard discard = new Discard("Discard_Snort");

		IProcessingBlock from = (Boolean.parseBoolean(props.getProperty(PROP_IN_USE_IFC))) ?
				fromDevice : fromDump;
		
		IProcessingBlock to = (Boolean.parseBoolean(props.getProperty(PROP_OUT_USE_IFC))) ?
				toDevice : toDump;
		
		List<IConnector> connectors = new ArrayList<>();
		List<IProcessingBlock> blocks = new ArrayList<>();
		
		blocks.addAll(ImmutableList.of(from, to, regex, classify, discard));
		connectors.addAll(ImmutableList.of(
			new Connector.Builder().setSourceBlock(from).setSourceOutputPort(0).setDestBlock(classify).build(),
			new Connector.Builder().setSourceBlock(classify).setSourceOutputPort(0).setDestBlock(regex).build(),
			new Connector.Builder().setSourceBlock(classify).setSourceOutputPort(1).setDestBlock(to).build()
		));

		IProcessingBlock postRegexBlock = discard;
		
		if (Boolean.parseBoolean(props.getProperty(PROP_ALERT))) {
			blocks.add(alert);
			postRegexBlock = alert;
			connectors.add(new Connector.Builder().setSourceBlock(alert).setSourceOutputPort(0).setDestBlock(discard).build());
	 	}
		
		int i;
		for (i = 0; i < regexRules.size() - 1; i++) {
			connectors.add(
					new Connector.Builder().setSourceBlock(regex)
										   .setSourceOutputPort(i)
										   .setDestBlock(postRegexBlock).build()
				);
		}
		// Connect default regex rule to 'to' - do not drop packets on that rule
		connectors.add(new Connector.Builder().setSourceBlock(regex).setSourceOutputPort(i).setDestBlock(to).build());
		
		int segment;
		try {
			segment = Integer.parseInt(props.getProperty(PROP_SEGMENT));
		} catch (NumberFormatException e) {
			segment = Integer.parseInt(DEFAULT_SEGMENT);
			LOG.info("Error parsing segment property. Using default segment: " + segment);
		}
		
		IStatement st = new Statement.Builder()
			.setLocation(TopologyManager.getInstance().resolve(segment))
			.setProcessingGraph(new ProcessingGraph.Builder().setBlocks(blocks).setConnectors(connectors).setRoot(from).build())
			.build();
		
		return Collections.singletonList(st);
	}
	
	private class InstanceUpHandler implements IInstanceUpListener {

		@Override
		public void Handle(InstanceUpArgs args) {
			LOG.info("Instance up for Snort: " + args.getInstance().toString());	
		}
	}

}
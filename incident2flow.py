# Imports
import json
from pprint import pprint
from collections import OrderedDict, defaultdict
from rdflib import Graph, Namespace
from rdflib.term import Literal, URIRef#, _castPythonToLiteral
from rdflib.namespace import RDF, RDFS, OWL, XSD
import uuid
from urllib.parse import quote, unquote
import logging
import re

class i2af():
    af_ns = None
    veris_ns = None
    exclusions = ["incident_id", "plus.master_id", "plus.created", "plus.analyst", "summary"]
    data_props = None
    obj_props = None
    anchor_map = None
    # below are specific to each instance. May not want to keep them in the class
    enum_iterator = defaultdict(int)
    instances = defaultdict(set)
    i_ns = None
    flowURI = None
    incident = None


    def __init__(
        self,
        schema_filename,
        attack_flow_namespace="https://vz-risk.github.io/flow/attack-flow#",
        veris_namespace="https://veriscommunity.net/attack-flow#"
        ):

        # create namespace from victim_id
        self.af_ns = Namespace(attack_flow_namespace)
        self.veris_ns = Namespace(veris_namespace)

        # open veris schema
        veris = Graph()
        veris.parse(schema_filename)
        # Get object and data properties so we know which are which when parsing them out of the incident
        query = ("""SELECT DISTINCT  ?p 
        WHERE { 
          ?p rdf:type owl:ObjectProperty .
        }""")
        qres = veris.query(query)
        self.obj_props = list(qres)
        self.obj_props = [item[0].split("#")[1] for item in self.obj_props]
        query = ("""SELECT DISTINCT  ?p 
        WHERE { 
          ?p rdf:type owl:DatatypeProperty .
        }""")
        qres = veris.query(query)
        self.data_props = list(qres)
        self.data_props = [item[0].split("#")[1] for item in self.data_props]   
        # all we needed were the property lists
        del(veris)

        # to map from veris_ns to attack flow ns
        self.anchor_map = {
            "action": self.af_ns["action"],
            "asset": self.af_ns["asset"],
            "extra": self.af_ns["property"]
        }


    def recurse_instances(self, d, lbl, owl, exclusions=[]):
        for k, v in d.items():
            try:
                if type(v) in [OrderedDict, dict]:
                    #keys = keys.union(recurse_keys(v, (lbl + (k,)), keys))
                    self.recurse_instances(v, (lbl + (k,)), owl, exclusions=exclusions)
                elif type(v) is list: 
                    for item in v:
                        if type(item) == dict:
                            #print("label: {0}, key: {1}, item: {2}".format(lbl, k, item))
                            self.recurse_instances(item, (lbl + (k,)), owl, exclusions=exclusions)
                        elif k == "variety":
                            # convert it to a class instance of the parent class
                            # add it to the incident
                            self.enum_iterator[".".join(lbl + (k, item))] += 1 # `lbl + (k, item)` used to be `item`
                            instance_name = quote(item + "_" + str(self.enum_iterator[".".join(lbl + (k, item))])) # `".".join(lbl + (k, item))` used to be `item`
                            
                            # define instance as an instance and an instance of something
                            owl.add((self.i_ns[instance_name], RDF.type, OWL.NamedIndividual))
                            owl.add((self.i_ns[instance_name], RDF.type, self.anchor_map.get(".".join(lbl), veris_ns[quote(".".join(lbl + (k,item)))])))
                            
                            # Connect instance to flow
                            owl.add((self.i_ns[instance_name], self.af_ns['flow'], self.flowURI))

                            # if action:
                            if lbl[0] == "action":
                                # (type) = 'action'
                                # name = instance_name
                                # description
                                owl.add((self.i_ns[instance_name], self.af_ns["description.action"], Literal(self.incident["action"][lbl[1]].get("notes", "no decription"))))
                                # logic_operator = ""
                                owl.add((self.i_ns[instance_name], self.af_ns['logic_operator'], Literal("OR")))
                elif k == "variety":
                    # convert it to a class instance of the parent class
                    # add it to the incident
                    instance_name = re.sub("[^0-9a-zA-Z_.\-~]+", "_", ".".join(lbl + (k, v))) # '".".join(lbl + (k, v))' used to be `v`
                    if lbl[0] == "asset" and v not in ["Unknown", "Other"]:
                        instance_name = instance_name[4:]
                    self.enum_iterator[instance_name] += 1
                    instance_name = quote(instance_name + "_" + str(self.enum_iterator[instance_name]))

                    # define instance as an instance and an instance of something
                    owl.add((self.i_ns[instance_name], RDF.type, OWL.NamedIndividual))
                    owl.add((self.i_ns[instance_name], RDF.type, self.anchor_map.get(".".join(lbl), veris_ns[quote(".".join(lbl + (k,v)))])))

                    # Connect instance to flow
                    owl.add((self.i_ns[instance_name], self.af_ns['flow'], self.flowURI))
            except:
                print("label: {0}, key: {1}, value: {2}".format(lbl, k, v))
                raise
                          
        return owl
                            
                            
    def recurse_properties(self, d, lbl, owl, exclusions=[]):
        for k, v in d.items():
            try:
                if type(v) in [OrderedDict, dict]:
                    owl = self.recurse_properties(v, (lbl + (k,)), owl, exclusions=exclusions)
                    
                elif k == "variety":
                    pass # varieties are all instances and should already be handled
                
                elif (type(v) is list):
                    for item in v:
                        if type(item) == dict:
                            self.recurse_properties(item, (lbl + (k,)), owl, exclusions=exclusions)
                        else:
                            # define it's flow
                            owl.add((self.veris_ns[quote(".".join(lbl + (k, item)))], self.af_ns['flow'], self.flowURI))
                            
                            # if we know what instance it goes to, connect it.
                            if str(self.veris_ns[quote(".".join(lbl))]) in self.instances.keys() and len(self.instances[str(self.veris_ns[quote(".".join(lbl))])]) == 1:
                                owl.add((self.instances[str(self.veris_ns[quote(".".join(lbl))])][0], self.veris_ns[quote(".".join(lbl + (k, )))], self.veris_ns[quote(".".join(lbl + (k, item)))]))
                elif (".".join((lbl + (k,str(v)))) in exclusions):
                    pass
                
                else:
                    if quote(".".join(lbl + (k,))) in self.obj_props:
                        if str(self.veris_ns[quote(".".join(lbl))]) in self.instances.keys() and len(self.instances[str(self.veris_ns[quote(".".join(lbl))])]) == 1:
                            owl.add((self.instances[str(self.veris_ns[quote(".".join(lbl))])][0], self.veris_ns[quote(".".join(lbl + (k, )))], self.veris_ns[quote(".".join(lbl + (k, v)))]))
                        else:
                            owl.add((self.veris_ns[quote(".".join(lbl[:-1]))], self.af_ns['flow'], self.flowURI))
                            owl.add((self.veris_ns[quote(".".join(lbl[:-1]))], self.veris_ns[quote(".".join(lbl + (k, )))], self.veris_ns[quote(".".join(lbl + (k, v)))]))
                    elif quote(".".join(lbl + (k,))) in self.data_props:
                        if str(self.veris_ns[quote(".".join(lbl))]) in self.instances.keys() and len(self.instances[str(self.veris_ns[quote(".".join(lbl))])]) == 1:
                            owl.add((self.instances[str(self.veris_ns[quote(".".join(lbl))])][0], self.veris_ns[quote(".".join(lbl + (k, )))], Literal(v)))
                        else:
                            owl.add((self.veris_ns[quote(".".join(lbl))], self.af_ns['flow'], self.flowURI))
                            owl.add((self.veris_ns[quote(".".join(lbl))], self.veris_ns[quote(".".join(lbl + (k, )))], Literal(v)))
                    else:
                        logging.warning("{0} is not in the object property or datatype property lists.".format(".".join(lbl + (k,))))
                                  
            except:
                print("label: {0}, key: {1}, value: {2}".format(lbl, k, v))
                raise
                   
        return owl


    def guess_temporal_relationships(self, incident, owl):
        ### Ok, there's going to be a _lot_ going on here...
        
        ### Event chain uses wierd stuff so we'll need to look it up to convert it to what's used 
        #    in the main schema (and hense the graph)
        event_chain_lookup = {
            "ext": "external", "int": "internal", "prt": "partner", "unk": "Unknown",
            "env": "environmental", "err": "Error", "hak": "hacking", "soc": "Social", 
            "mal": "malware", "mis": "misuse", "phy": "Physical",
            "au": "availability", "cp": "confidentiality", "ia": "integrity",
            "emb": "E", "med": "M", "net": "N", "ppl": "P", "srv": "S", "ter": "T", "usr": "U"
        }
        
        
        # We also need to collect all the named individuals for multiple reasons
        query = ("""SELECT DISTINCT  ?inst ?thing
        WHERE { 
          ?inst rdf:type owl:NamedIndividual .
          ?inst rdf:type ?thing .
           FILTER (?thing != owl:NamedIndividual)
        }""")
        qres = owl.query(query)
        res = list(qres)
        
        # NOTE: these are the instances.  They don't tel you what type of action they are.
        # This is mostly useful if there's just 1 action and asset
        actions = [item[0] for item in res if item[1].split("#")[1].startswith("action")]
        assets = [item[0] for item in res if item[1].split("#")[1].startswith("asset")]
        attributes = [item[0] for item in res if item[1].split("#")[1].startswith("attribute")]

        # So we'll start with the event chain
        # Just because it has an event chaind oesn't mean we'll which go in what order...
        if "event_chain" in incident['plus']:
            # first we're going to need to count the number of time each type of actin/asset/attribute occurs
            # this is important because if we have multiple occurrences of any of these things it'll be hard
            # to tell what step they go with.
            occurrence_counts = {
    #            "incident": {
    #                "action": defaultdict(int),
    #                "asset": defaultdict(int),
    #                "attribute": defaultdict(int)
    #            },
                "oincident": {
                    "action": defaultdict(list),
                    "asset": defaultdict(list),
                    "attribute": defaultdict(list)
                }
            }
            for action in [(item[0], item[1].split("#")[1]) for item in res if item[1].split("#")[1].startswith("action")]:
                occurrence_counts['oincident']['action'][action[1].split(".")[1]].append(action[0])
            for asset in [(item[0], item[1].split("#")[1]) for item in res if item[1].split("#")[1].startswith("asset")]:
                occurrence_counts['oincident']['asset'][asset[1].split(".")[3].split("%20-%20")[0]].append(asset[0])
            for attribute in [(item[0], item[1].split("#")[1]) for item in res if item[1].split("#")[1].startswith("attribute")]:
                occurrence_counts['oincident']['attribute'][attribute[1].split(".")[1]].append(attribute[0])
    #        for step in incident['plus']['event_chain']:
    #            occurrence_counts['incident']['action'][step.get("action", "Unknown")] += 1
    #            occurrence_counts['incident']['asset'][step.get("asset", "Unknown")] += 1
    #            occurrence_counts['incident']['attribute'][step.get("attribute", "Unknown")] += 1
                
            #print(occurrence_counts)

    ### Block below using it seems unneeded
    #        # One way we can parse is, even if something like an asset occurs multiple places in the 
    #        # event chain, if there's only 1 instance of an asset, we know that asset goes to each
    #        # both locations in the chain.
    #        dup_but_can_parse = True
    #        for a in ['action', 'asset', 'attribute']:
    #            for k,v in occurrence_counts['incident'][a].items():
    #                if v > 1 and len(occurrence_counts['oincident'][a][event_chain_lookup[k]]) > 1:
    #                    dup_but_can_parse = False

            
            # first we'll check if there's just 1 step.  If there's just one step we know everything goes to that step.
            ### NOTE: I think this is duplicative with below
            #if len(incident['plus']['event_chain']) == 1 and len(actions) == 1 and len(assets) == 1:
            #    print("can parse because only 1 step")
            

            # If there's more steps, but each action/asset/attribute only occur once in it, we can map instances to it
            if (#all([v <= 1 for k,v in occurrence_counts['incident']['action'].items()]) and 
                #  all([v <= 1 for k,v in occurrence_counts['incident']['asset'].items()]) and
                #  all([v <= 1 for k,v in occurrence_counts['incident']['attribute'].items()]) and 
                  all([len(v) <= 1 for k,v in occurrence_counts['oincident']['action'].items()]) and 
                  all([len(v) <= 1 for k,v in occurrence_counts['oincident']['asset'].items()]) and 
                  all([len(v) <= 1 for k,v in occurrence_counts['oincident']['attribute'].items()])):
                logging.info("can parse because each item only occurs once.")
                old_asset = None
                for step in incident['plus']['event_chain']:
                    attribute = occurrence_counts['oincident']['attribute'].get(event_chain_lookup[step.get('attribute', "unk")], self.veris_ns + "attribute.unknown")
                    action = occurrence_counts['oincident']['action'].get(event_chain_lookup[step.get('action', "unk")], None)
                    asset = occurrence_counts['oincident']['asset'].get(event_chain_lookup[step.get('asset', "unk")], None)
                    if all([action, asset]):
                        owl.add((URIRef(attribute), RDFS.subPropertyOf, self.af_ns['state_change']))
                        owl.add((URIRef(action), URIRef(attribute), URIRef(asset)))
                    if old_asset:
                        owl.add((URIRef(old_asset), self.veris_ns["attribute.unknown"], URIRef(action)))
                    old_asset = asset
                    

    ### I think below is equivalent to the above block with the 3 lines commented out so unneeded
    #        # as noted above, if we have duplicates, we can still map to it as noted above
    #        elif dup_but_can_parse:
    #            for step in event_chain
    #            print("can parse because even though duplicate items, they link to only one instance")

        
        # if only one action & asset, you can assume the sequence
        elif len(assets) == 1 and len(actions) == 1:
            logging.info("Can parse single action/asset.")
            for attribute in attributes:
                owl.add((URIRef(attribute), RDFS.subPropertyOf, self.af_ns['state_change']))
                owl.add((URIRef(actions[0]), URIRef(attribute), URIRef(assets[0])))
                
        else:
            #print("No available logic to sequence actions and assets.")
            logging.warning("No available logic to sequence actions and assets.")
        
        return(owl)


    def incident_to_owl(self, incident):
        self.incident = incident

        # create namespace from victim_id
        i_ns = incident['victim'].get('victim_id', uuid.uuid4()).lower()
        i_ns = re.sub("[^0-9a-zA-Z_.\-~]+", "_", i_ns)
        i_ns = Namespace("urn:absolute:" + quote(i_ns) + "#")
        self.i_ns = i_ns
        
        # to number instances
        self.enum_iterator = defaultdict(int)
        
        # start the incident's graph
        owl = Graph()
        
        ### create any manditory fields in AF
        # Create flow instance, flow id
        flowURI = i_ns[incident['plus']['master_id']] # to object
        owl.add((flowURI, RDF.type, OWL.NamedIndividual))
        owl.add((flowURI, RDF.type, self.af_ns['attack-flow']))
        # flow name literal
        owl.add((flowURI, self.af_ns['name.attack-flow'], Literal(incident['incident_id'])))
        # flow created literal
        owl.add((flowURI, self.af_ns['created'], Literal(incident['plus'].get("created", "1970-01-01T01:00:00Z"))))
        # flow author literal
        owl.add((flowURI, self.af_ns['author'], Literal(incident['plus'].get("analyst", "Unknown"))))
        # flow description literal
        owl.add((flowURI, self.af_ns['description.attack-flow'], Literal(incident['summary'])))
        self.flowURI = flowURI


        self.recurse_instances(incident, (), owl, exclusions=self.exclusions)
        
        query = ("""SELECT DISTINCT  ?inst ?thing
        WHERE { 
          ?inst rdf:type owl:NamedIndividual .
          ?inst rdf:type ?thing .
           FILTER (?thing != owl:NamedIndividual)
        }""")
        qres = owl.query(query)
        self.instances = defaultdict(set)
        for inst,thing in qres:
            self.instances[str(thing)].add(str(inst))
        self.instances = dict()
        self.instances = {".".join(k.split(".")[:2]):list(v) for k,v in self.instances.items()}
        
        self.recurse_properties(incident, (), owl, exclusions=self.exclusions)    
        
        # Determine causal linkages between actions if possible (use value.chain and or single-action)
        owl.add((self.veris_ns["attribute.unknown"], RDFS.subPropertyOf, self.af_ns['state_change']))
        owl = self.guess_temporal_relationships(incident, owl)
        
        return(owl)


    def convert():
        pass # TODO: given a bunch of incidents, output a bunch of graphs


if __name__ == '__main__':
    pass # TODO: Set up a command line interface

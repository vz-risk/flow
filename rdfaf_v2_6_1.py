# NOTE: did not quote/unquote URIs because technically the json schema validates URIs, however this allows a LOT of room for abuse.
# V0.2.6.2
# author Gabriel Bassett

from rdflib import Graph, Namespace
from rdflib.namespace import RDF, RDFS, OWL
from rdflib.term import Literal, URIRef
import json
from jsonschema import validate, ValidationError # validate json schema
from collections import defaultdict
import logging
# may want to replace owlrl with reasonable when reasonable is more complete as owlrl is slow.
from owlrl import DeductiveClosure, OWLRL_Semantics, RDFS_OWLRL_Semantics 
#import reasonable # https://lib.rs/crates/reasonable

class flow():
    """ A class to convert attack flow to and from RDF OWL as well as validate both the JSON schema and ontological rules."""
    
    namespace = Namespace("https://flow-v1#")
    schema = None
    flow_json = None
    flow_rdf = None
    rules = Graph()

    def __init__(self):
        pass

    def load_namespace(self, namespace):
        """ Load a string as a namespace"""
        self.namespace = Namespace(namespace)


    def load_schema(self, schema):
        """ Loads the attack_flow schema."""
        if type(schema) != dict:
            raise TypeError("Please provide an already loaded json object for the schema.")

        self.schema = schema

        if 'rules' in schema:
            self.graph.parse(data=json.dumps(schema['rules']), format="json-ld")
            self.rules = self.graph.parse(data=json.dumps(schema['rules']), format="json-ld")


    def load_rules(self, rules):
        """ Stores an RDFlib graph into the rules."""
        self.rules = rules


    def add_rules(self, rules):
        """ Adds a graph from an OWL file into the rules graph"""
        self.rules.parse(rules)


    def load_flow(self, flow):
        """ Load the attack flow and validate it """
        if type(flow) == dict:
            validate(flow, self.schema)
            flow_graph = self.json_to_rdf(flow)
            self.validate_graph(flow_graph)
            self.flow_json = flow
            self.flow_rdf = flow_graph
        elif type(flow) == Graph:
            self.validate_graph(flow)
            flow_json = self.rdf_to_json(flow)
            validate(flow_json, self.schema)
            self.flow_json = flow_json
            self.flow_rdf = flow
        else:
            raise TypeError("Please provide an already loaded json object or rdflib graph for the flow.")


    def get_flow_graph(self, rules=False):
        """ return the rdf graph version of the flow."""
        if rules:
            flow = self.flow_rdf
            flow.parse(data=self.rules.serialize(format="xml"))
            return flow
        else:
            return self.flow_rdf


    def get_flow_json(self):
        """ return the JSON schema version of the flow"""
        return self.flow_json


    def json_to_rdf(self, flow_json):
        """Convert a flow represented in json schema to a flow represented by rdf triples"""
        flow_graph = Graph()

        if 'rules' in flow_json:
            self.graph.parse(data=json.dumps(flow_json['rules']), format="json-ld")

        # Flow
        flow_id = flow_json['flow']['id']
        flow_graph.add((self.namespace[flow_id], RDF.type, OWL.NamedIndividual))
        flow_graph.add((self.namespace[flow_id], RDF.type, self.namespace ['attack-flow']))
        for key in set(flow_json['flow'].keys()).intersection(["created", "author", "description",  "name"]):
            flow_graph.add((self.namespace[flow_id], self.namespace[key], Literal(flow_json['flow'][key])))

        # action
        actions = set()
        for action in flow_json['actions']:
            action_id = action['id'].split("//")[-1].split("#")[-1]
            actions.add(action_id)
            flow_graph.add((self.namespace[action_id], RDF.type, OWL.NamedIndividual))
            flow_graph.add((self.namespace[action_id], RDF.type, self.namespace.action))
            for key in set(action.keys()).intersection(["description", "logic_operator", "name", "reference", 
                                                        "timestamp", "succeeded", "confidence", 
                                                        "logic_operator_language"]):
                flow_graph.add((self.namespace[action_id], self.namespace[key], Literal(action[key])))
                flow_graph.add((self.namespace[action_id], self.namespace[key], Literal(action[key])))

        # asset
        assets = set()
        for asset in flow_json['assets']:
            asset_id = asset['id'].split("//")[-1].split("#")[-1]
            assets.add(asset_id)
            flow_graph.add((self.namespace[asset_id], RDF.type, OWL.NamedIndividual))
            flow_graph.add((self.namespace[asset_id], RDF.type, self.namespace.asset))
            for key in set(asset.keys()).intersection(["description", 'state']):
                flow_graph.add((self.namespace[asset_id], self.namespace[key], Literal(asset[key])))   
### For if 'state' is an object property rather than a data property            
#            if 'state' in asset.keys():
#                # NOTE: at some point we will likely want fancier parcing of stage for 'types' of state.
#                flow_graph.add((self.namespace[asset_id], self.namespace['state'], self.namespace[target_id]))
                

        # relationships and object properties
        for prop in ["relationships", "object_properties"]:
            for edge in flow_json[prop]:
                source_id = edge['source'].split("//")[-1].split("#")[-1]
                type_id = edge['type'].split("//")[-1].split("#")[-1]
                target_id = edge['target'].split("//")[-1].split("#")[-1]
                if source_id in actions:
                    if target_id in actions:
                        logging.warning("Edge <{0}, {1}, {2}> is between two actions.  This is not part of the attack flow schema and as such the edge will not be added".format(source_id, type_id, target_id))
                    elif type_id == "flow" and target_id != flow_id:
                        logging.warning("Edge <{0}, {1}, {2}> is a flow edge that does not point to an attack-flow.  This is not part of the attack flow schema and as such the edge will not be added".format(source_id, type_id, target_id))
                    elif target_id == flow_id:
                        if type_id != "flow":
                            logging.warning("Edge <{0}, {1}, {2}> does not have type 'flow' but points to an attack-flow.  Adding it with 'flow' as the type instead of '{1}'.".format(source_id, type_id, target_id))
                        flow_graph.add((self.namespace[source_id], self.namespace["flow"], self.namespace[target_id]))                            
                    elif target_id in assets:
                        flow_graph.add((self.namespace[source_id], self.namespace[type_id], self.namespace[target_id]))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[type_id], RDFS.subPropertyOf, self.namespace["state_requirement"]))
                        flow_graph.add((self.namespace[type_id], RDF.type, OWL.ObjectProperty))
                    else: # Property
                        flow_graph.add((self.namespace[source_id], self.namespace[type_id], self.namespace[target_id]))
                        flow_graph.add((self.namespace[target_id], RDF.type, OWL.NamedIndividual))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[target_id], RDFS.subClassOf, self.namespace['property']))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[type_id], RDFS.subPropertyOf, self.namespace["described_by"]))
                        flow_graph.add((self.namespace[type_id], RDF.type, OWL.ObjectProperty))
                elif source_id in assets:
                    if type_id == "flow" and target_id != flow_id:
                        logging.warning("Edge <{0}, {1}, {2}> is a flow edge that does not point to an attack-flow.  This is not part of the attack flow schema and as such the edge will not be added".format(source_id, type_id, target_id))
                    elif target_id == flow_id:
                        if type_id != "flow":
                            logging.warning("Edge <{0}, {1}, {2}> does not have type 'flow' but points to an attack-flow.  Adding it with 'flow' as the type instead of '{1}'.".format(source_id, type_id, target_id))
                        flow_graph.add((self.namespace[source_id], self.namespace["flow"], self.namespace[target_id]))
                    elif target_id in actions:
                        flow_graph.add((self.namespace[source_id], self.namespace[type_id], self.namespace[target_id]))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[type_id], RDFS.subPropertyOf, self.namespace["state_change"]))
                        flow_graph.add((self.namespace[type_id], RDF.type, OWL.ObjectProperty))
                    elif target_id in assets:
                        logging.warning("Edge <{0}, {1}, {2}> is between two assets.  It will be added as a contextual rather than causal (action->asset or asset->action) relationship".format(source_id, type_id, target_id))
                        flow_graph.add((self.namespace[source_id], self.namespace[type_id], self.namespace[target_id]))
                        flow_graph.add((self.namespace[target_id], RDF.type, OWL.NamedIndividual))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[type_id], RDFS.subPropertyOf, self.namespace["described_by"]))
                        flow_graph.add((self.namespace[type_id], RDF.type, OWL.ObjectProperty))
                    else: # property
                        flow_graph.add((self.namespace[source_id], self.namespace[type_id], self.namespace[target_id]))
                        flow_graph.add((self.namespace[target_id], RDF.type, OWL.NamedIndividual))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[target_id], RDFS.subClassOf, self.namespace['property']))
                        # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                        flow_graph.add((self.namespace[type_id], RDFS.subPropertyOf, self.namespace["described_by"]))
                        flow_graph.add((self.namespace[type_id], RDF.type, OWL.ObjectProperty))
                else: # if it's not an action or a asset, it's treated as a property (even if it's an attack-flow)
                    flow_graph.add((self.namespace[source_id], self.namespace[type_id], self.namespace[target_id]))
                    flow_graph.add((self.namespace[source_id], RDF.type, OWL.NamedIndividual))
                    # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                    flow_graph.add((self.namespace[source_id], RDFS.subClassOf, self.namespace['property']))
                    flow_graph.add((self.namespace[target_id], RDF.type, OWL.NamedIndividual))
                    # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                    flow_graph.add((self.namespace[target_id], RDFS.subClassOf, self.namespace['property']))
                    # NOTE: below should only be if type_id is not in rules already and is not in another namespace.
                    flow_graph.add((self.namespace[type_id], RDFS.subPropertyOf, self.namespace["described_by"]))
                    flow_graph.add((self.namespace[type_id], RDF.type, OWL.ObjectProperty))

        # data properties
        for prop in flow_json['data_properties']:
            source_id = prop['source'].split("//")[-1].split("#")[-1]
            type_id = prop['type'].split("//")[-1].split("#")[-1]
            flow_graph.add((self.namespace[source_id], self.namespace[type_id], Literal(prop['target'])))
            flow_graph.add((self.namespace[type_id], RDF.type, OWL.DatatypeProperty))

        return flow_graph


    def rdf_to_json(self, flow_graph):
        
        # Flows
        # Property flows
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) + 
        """SELECT DISTINCT  ?s ?o ?p
        WHERE { 
          ?s  rdf:type  af:attack-flow . 
          ?s ?o ?p .
          ?o rdf:type owl:DatatypeProperty .
        }""")
        qres = flow_graph.query(query)
        flows = defaultdict(dict)
        for triple in qres:
            flow_id = triple[0].split("#")[-1]
            key = triple[1].split("#")[-1]
            value = triple[2].split("#")[-1]
            flows[flow_id]['id'] = str(triple[0])
            flows[flow_id][key] = value
            flows[flow_id]["type"] = "attack-flow"
        # No-property flows
        query = ("PREFIX  af:<{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s
        WHERE { 
          ?s  rdf:type  af:attack-flow . 
        }""")
        qres = flow_graph.query(query)
        for fl in qres:
            flow_id = str(fl[0])
            flows[flow_id]['id'] = flow_id
        flows = [v for k,v in flows.items()]

        # Actions
        query = ("PREFIX  af: <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s ?o ?p
        WHERE { 
          ?s  rdf:type  af:action . 
          ?s ?o ?p .
          ?o rdf:type owl:DatatypeProperty .
        }""")
        qres = flow_graph.query(query)
        actions = defaultdict(dict)
        for triple in qres:
            action_id = triple[0].split("#")[-1]
            key = triple[1].split("#")[-1]
            value = triple[2].split("#")[-1]
            actions[action_id]['id'] = str(triple[0])
            actions[action_id][key] = value
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s
        WHERE { 
          ?s  rdf:type  af:action . 
        }""")
        qres = flow_graph.query(query)
        for action in qres:
            action_id = action[0].split("#")[-1]
            actions[action_id]['id'] = str(action[0])
        actions = [v for k,v in actions.items()]

        # Assets
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s ?o ?p
        WHERE { 
          ?s  rdf:type  af:asset . 
          ?s ?o ?p .
          ?o rdf:type owl:DatatypeProperty .
        }""")
        qres = flow_graph.query(query)
        assets = defaultdict(dict)
        for triple in qres:
            asset_id = triple[0].split("#")[-1]
            key = triple[1].split("#")[-1]
            value = triple[2].split("#")[-1]
            assets[asset_id]['id'] = str(triple[0])
            assets[asset_id][key] = value        
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s
        WHERE { 
          ?s  rdf:type  af:asset . 
        }""")
        qres = flow_graph.query(query)
        for asset in qres:
            asset_id = asset[0].split("#")[-1]
            assets[asset_id]['id'] = str(asset[0])  
### for if state is an object property rather than a data property
#        qres = flow_graph.query(("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
#                """SELECT DISTINCT  ?s ?p
#                WHERE { 
#                  ?s  rdf:type  af:asset . 
#                  ?s  af:state ?p . 
#                }"""))
#        qres2 = defaultdict(list)
#        for tupl in qres:
#            qres2[tupl[0].split("#")[-1]].append(str(tupl[1]))
#        for asset in qres2:
#            # NOTE: the below only adds the first state URI. State should probably be moved to a manditory property like 'flow'.
#            assets[asset]['state'] = qres2[asset][0] 
        assets = [v for k,v in assets.items()]

        # Object Properties
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s ?o ?p
        WHERE {
          {
            ?o rdfs:subPropertyOf* af:described_by .
            ?s ?o ?p 
          } FILTER NOT EXISTS {
            ?s af:flow ?p .
          }
        }""")
        object_properties = []
        qres = flow_graph.query(query)
        for triple in qres:
            source = str(triple[0]) # .split("#")[-1]
            type_ = str(triple[1]) # .split("#")[-1]
            target = str(triple[2]) # .split("#")[-1]
            object_properties.append({
                "source": source,
                "type": type_,
                "target": target
            })

        # Data Properties
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s ?o ?p
         WHERE {
          {
            ?o rdf:type owl:DatatypeProperty .
            ?s ?o ?p 
          } 
        }""")
        data_properties = []
        qres = flow_graph.query(query)
        for triple in qres:
            source = str(triple[0]) # .split("#")[-1]
            type_ = str(triple[1]) # .split("#")[-1]
            target = str(triple[2]) # .split("#")[-1]
            data_properties.append({
                "source": source,
                "type": type_,
                "target": target
            })

        # relationships
        query = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        """SELECT DISTINCT  ?s ?o ?p
        WHERE {
          {
            ?s  rdf:type  af:asset . 
            ?p  rdf:type  af:action . 
            ?s ?o ?p 
          } UNION {
            ?s  rdf:type  af:action . 
            ?p  rdf:type  af:asset . 
            ?s ?o ?p 
          } UNION {
            ?s rdf:type af:asset .
            ?p rdf:type af:attack-flow .
            ?s ?o ?p
          } UNION {
            ?s rdf:type af:action .
            ?p rdf:type af:attack-flow .
            ?s ?o ?p
          } FILTER NOT EXISTS {
            ?o rdfs:subPropertyOf* af:described_by .
          }
        }""")
        relationships = []
        qres = flow_graph.query(query)
        for triple in qres:
            source = str(triple[0])
            type_ = str(triple[1])
            target = str(triple[2])
            relationships.append({
                "source": source,
                "type": type_,
                "target": target
            })

        flow_json = {
            "$schema": "../schema/attack-flow-2021-11-03-draft.json",
            "flow": flows[0],
            "actions": actions,
            "assets": assets,
            "relationships": relationships,
            "object_properties": object_properties,
            "data_properties": data_properties,
            "rules": self.rules
        }

        return flow_json


    def validate_graph(self, graph):
        """Given an rdf graph, validate a few rules by SPARQL and return invalid edges"""
        ret = []

        sel = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        "SELECT DISTINCT  ?s ?o ?p\n" +
        "WHERE {where}")
        ask = ("PREFIX  af:  <{af}>\n".format(af=self.namespace) +
        "ASK {where}")

        ### action -/-> action
        where = """{ 
          ?s  rdf:type  af:action . 
          ?s ?o ?p .
          ?p rdf:type af:action .
        }"""
        qres = graph.query(ask.format(where=where))
        for res in qres:
            if res:
                yield ValidationError("NOT ALLOWED action->action relationship found.")
        qres = graph.query(sel.format(where=where))
        ret += list(qres)

        ### asset -/-> asset
        where = """{
          {
            ?s  rdf:type  af:asset . 
            ?s ?o ?p .
            ?p rdf:type af:asset .
          } FILTER NOT EXISTS {
            ?o rdfs:subPropertyOf* af:described_by .
          }
        }""" # modified for subPropertyOf search
        qres = graph.query(ask.format(where=where))
        for res in qres:
            if res:
                yield ValidationError("NOT ALLOWED asset->asset relationship found.")
        qres = graph.query(sel.format(where=where))
        ret += list(qres)

        ### action/asset -flow-> attack-flow
        where = """{
          {
            ?s  rdf:type  af:asset . 
            ?s ?o ?p .
          } UNION { 
            ?s  rdf:type  af:action . 
            ?s ?o ?p .
          }
          FILTER NOT EXISTS {
            ?p af:flow ?p1 .
            ?p1 rdf:type af:attack-flow .
          }
        }"""
        qres = graph.query(ask.format(where=where))
        for res in qres:
            if res:
                yield ValidationError("Actions or Assets without 'flow' relationships to an attack-flow found.")
        qres = graph.query(sel.format(where=where))
        ret += list(qres)

        ### asset -state-> property
        where = """{
          {
            ?s af:state ?p .
          }
          FILTER NOT EXISTS {
            ?s  rdf:type  af:asset . 
            isLiteral(?p)
          }
        }"""
### FOr where state is an object property rather than a data property
#        where = """{
#          {
#            ?s af:state ?p .
#          }
#          FILTER NOT EXISTS {
#            ?s  rdf:type  af:asset . 
#            ?p rdfs:subClassOf af:property .
#          }
#        }"""
        qres = graph.query(ask.format(where=where))
        for res in qres:
            if res:
                yield ValidationError("Property with type:state that does not connect an asset to a property.")
        qres = graph.query(sel.format(where=where))
        ret += list(qres)

        return list(ret)

    
    def reason(self):
        """Reason over the flow_rdf to add inferred triples."""
        ### OWL-RL
        DeductiveClosure(RDFS_OWLRL_Semantics).expand(self.flow_rdf)


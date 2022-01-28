# License: MIT License
# VERSION: 0.1

### Imports ###
#import jsonschema
import json
import argparse
import logging
#import copy
#import os
#import importlib
#import imp
#from collections import OrderedDict
from rdflib import Graph, Namespace
from rdflib.term import Literal, URIRef#, _castPythonToLiteral
from rdflib.namespace import RDF, RDFS, OWL, XSD
#import re
from urllib.parse import quote, unquote
import pandas as pd
import logging

cfg = {
    'log_level': 'warning',
    'log_file': None,
    'mergedfile': "../verisc-merged.json",
    'output': "../verisc-owl.json",
    'check': False,
    'repositories': "",
    'join': True
}


class veris2af():
    anchor_map = None
    asset_map = {
        "U": "user device",
        "S": "server",
        "T": "public terminal",
        "P": "people",
        "M": "media",
        "E": "embedded",
        "N": "network",
        "O": "Other"
    }
    type_map = {
        "string": XSD.string,
        "number": XSD.float,
        "boolean": XSD.boolean,
        "integer": XSD.integer
    }
    schema = None
    labels = None
    veris_ns = None
    af_ns = None
    veris_graph = Graph()

    def __init__(self,
            veris=None,
            veris_labels=None,
            veris_namespace="https://veriscommunity.net/attack-flow#",
            attack_flow_namespace="https://vz-risk.github.io/flow/attack-flow#"
        ):
        self.schema = veris
        self.labels = veris_labels
        self.veris_ns = Namespace(veris_namespace)
        self.af_ns = Namespace(attack_flow_namespace)

        self.anchor_map = {
            "action": self.af_ns["action"],
            "asset": self.af_ns["asset"],
            "extra": self.af_ns["property"]
        } 


    ### Functions ###
    def deepGetAttr(self, od, name):
        if len(name) > 1:
            return self.deepGetAttr(od[name[0]], name[1:])
        else:
            return od[name[0]]

    def veris_to_owl_r(self, d, lbl, name, g):
        #print(f"starting {name}")
        try:
            #parent = name.split(".")[-2]
            parent = ".".join(name.split(".")[:-1])
        except:
            parent = ""
        child = name.split(".")[-1]
        references = set(g.subjects()).union(g.objects()).union(g.predicates())
        try:
            # for objects we'll recurse into them
            if d['type'] == "object":
                lbl = lbl + "properties."
                # for most things create the parent-child paths
                if child != "" and child not in self.anchor_map: # don't include things that are mapped to other classes
                    # If it's the root, link to properties
                    if parent == "":
                        g.add((self.veris_ns[quote(name)], RDFS.subClassOf, self.af_ns["property"]))
                    # if the parent is an one of the special places to anchor, replace the parent with the anchor
                    elif parent in self.anchor_map:
                        g.add((self.veris_ns[quote(name)], RDFS.subClassOf, self.anchor_map[parent]))
                    # else link the parent and the child
                    else:
                        g.add((self.veris_ns[quote(name)], RDFS.subClassOf, self.veris_ns[quote(parent)]))
                    if 'description' in d:
                        g.add((self.veris_ns[quote(name)], RDFS.comment, Literal(d['description'])))
                    # label the child
                    g.add((self.veris_ns[quote(name)], RDFS.label, Literal(child)))
                # recurse into the properties
                for k, v in d['properties'].items():
                    #print([k, v])
                    self.veris_to_owl_r(v, lbl, name + "." + k, g)
            # If instead of an object it's an array, just recurse the items and treat them as strings, etc
            elif d['type'] == "array":
                lbl = lbl + "items."
                self.veris_to_owl_r(d['items'], lbl, name, g)
                #TODO: add the veris_ns[name] list as an object property of the main key (same or higher level)
            elif d['type'] in ["string", "number", "boolean", "integer"] or (d['type']): 
                # if the string doesn't have options, add it as a data property
                if 'enum' not in d: # literals
                    # If it doesn't already exist, give it a type, mark it a Data Property, and give it a literal name. Then link it to it's parent
                    if self.veris_ns[quote(name)] not in references:
                        g.add((self.veris_ns[quote(name)], RDF.type, OWL.DatatypeProperty))
                        g.add((self.veris_ns[quote(name)], RDFS.range, self.type_map[d['type']]))
                        g.add((self.veris_ns[quote(name)], RDFS.label, Literal(child)))
                        if 'description' in d:
                            g.add((self.veris_ns[quote(name)], RDFS.comment, Literal(d['description'])))
                    # Link to the appropriate parent (top of namespace, anchor point, or parent)
                    if parent == "":
                        g.add((self.veris_ns[quote(name)], RDFS.domain, self.af_ns["attack-flow"]))
                    elif parent in self.anchor_map:
                        g.add((self.veris_ns[quote(name)], RDFS.domain, self.anchor_map[parent]))
                    else:
                        g.add((self.veris_ns[quote(name)], RDFS.domain, self.veris_ns[quote(parent)]))
                # if this is one of the main enumerations.
                elif child == "variety":
                    for enum in d['enum']:
                        # Assets is special so we have to treat it special
                        if parent == "assets":
                            #if enum != "Other" and enum != "Unknown": # because unknown/other don't start with a a letter representing the parent
                            if True:
                                g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.subClassOf, self.veris_ns[quote(self.asset_map[enum[0]])]))
                                g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.label, Literal(enum[4:])))
                        # In case we have to handle attribute differently since it's a list of objects...
    #                    elif name.startswith(".attribute"):
    #                        g.add((veris_ns[quote(enum)], RDFS.subPropertyOf, veris_ns[quote(parent)]))
    #                        g.add((veris_ns[quote(enum)], RDFS.label, Literal(enum)))
                        # otherwise just connect the enumerations directly
                        else:
                            g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.subClassOf, veris_ns[quote(parent)]))
                            g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.label, Literal(enum)))
                        # try and get the definition from the labels file and add it as a comment. Otherwise, pass.
                        try:
                            value = self.deepGetAttr(self.labels, f"{name}.{enum}"[1:].split("."))
                            g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.comment, Literal(value)))
                        except KeyError:
                            pass
                else: # non-main enumerations
                    # create a thing with name + enum as a subclass of lists to store the enumerations
                    # create a object property type of name+enum w/ subclass of 'lists' to point to the enumeration
                    g.add((self.veris_ns[quote(name + "Enum")], RDFS.subClassOf, veris_ns['lists']))
                    g.add((self.veris_ns[quote(name + "Enum")], RDFS.label, Literal(name)))
                    g.add((self.veris_ns[quote(name)], RDF.type, OWL.ObjectProperty))
                    g.add((self.veris_ns[quote(name)], RDFS.label, Literal(name)))
                    if parent == "":
                        g.add((self.veris_ns[quote(name)], RDFS.domain, self.af_ns["attack-flow"]))
                    elif parent in self.anchor_map:
                        g.add((self.veris_ns[quote(name)], RDFS.domain, self.anchor_map[parent]))
                    else:
                        g.add((self.veris_ns[quote(name)], RDFS.domain, self.veris_ns[quote(parent)]))
                    g.add((self.veris_ns[quote(name)], RDFS.range, self.veris_ns[quote(name + "Enum")]))
                    for enum in d['enum']:
                        # based on https://stackoverflow.com/questions/18785499/modelling-owl-datatype-property-restrictions-with-a-list-of-values
                        g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.subClassOf,veris_ns[quote(name + "Enum")]))
                        g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.label, Literal(enum)))
                        try:
                            value = self.deepGetAttr(self.labels, f"{name}.{enum}"[1:].split("."))
                            g.add((self.veris_ns[quote(f"{name}.{enum}")], RDFS.comment, Literal(value)))
                        except KeyError:
                            pass
                    if parent == "":
                        g.add((self.veris_ns[quote(child)], RDFS.domain, self.af_ns["attack-flow"]))
                    elif parent in self.anchor_map:
                        g.add((self.veris_ns[quote(child)], RDFS.domain, self.anchor_map[parent]))
                    else:
                        g.add((self.veris_ns[quote(child)], RDFS.domain, self.veris_ns[quote(parent)]))

            else:
                logging.warning("json schema type 'null' not currently supported. d: {0}, lbl: {1}, name: {2}, parent: {3}".format(d, lbl, name, parent))
        except:
            print("d: {0}, lbl: {1}, name: {2}".format(d, lbl, name))
            raise
        return g


    def veris_to_owl(self, veris=None):
        # Start Graph
        if veris is None:
            veris = self.veris_graph

        # Add top level stuff
        veris.add((self.veris_ns['lists'], RDFS.subClassOf, self.af_ns["property"])) # list holder within properties
        for asset in self.asset_map: # assets (since they aren't actually in VERIS)
            veris.add((self.veris_ns[quote(self.asset_map[asset])], RDFS.subClassOf, self.veris_ns['assets']))

        # Convert VERIS to OWL
        self.veris_graph = self.veris_to_owl_r(self.schema, "", "", veris)


    def add_af(self, attack_flow):
        self.veris_graph.parse(attack_flow) # do we _really_ want to add all of Att&ckflow or just what we need to add? Maybe an option?


    def veris_to_atk(self, veris_atk_map, atk_namespace):
        veris = self.veris_graph
        atk_ns = Namespace(atk_namespace)

        # Add ATT&CK Equivalence
        # Add some basic att&ck stuff
        veris.add((self.atk_ns['technique'], RDFS.subClassOf, self.atk_ns["action"]))
        veris.add((self.atk_ns['name'], RDF.type, OWL.DatatypeProperty))
        # Add attack -> Veris
        for k, v in self.atk_map['attack_to_veris'].items():
            veris.add((self.atk_ns[k], RDFS.subClassOf, self.atk_ns['technique']))
            veris.add((self.atk_ns[k], self.atk_ns['name'], Literal(v['name'])))
            # the mapping doesn't account for these changes in VERIS 1.3.6
            for enum in v['veris']:
                enum = {
                    "action.hacking.variety.HTTP Response Splitting": "action.hacking.variety.HTTP response splitting",
                    "action.hacking.variety.Use of backdoor or C2": "action.hacking.vector.Backdoor",
                    "action.hacking.vector.Backdoor or C2": "action.hacking.vector.Backdoor",
                    "action.hacking.variety.Footprinting": "action.hacking.variety.Profile host"
                }.get(enum, enum) # fix some changes since the mapping
                # If variety remove the 'variety' since we don't include them in the OWL version
                if "variety" in enum:
                    veris.add((atk_ns[k], OWL.equivalentClass, self.veris_ns[quote(enum.split(".")[-1])]))
                else:
                    veris.add((atk_ns[k], OWL.equivalentClass, self.veris_ns[quote("." + enum)]))

        # get the table fixed up. (It's kinda a mess the way it's created)
        veris_atk = pd.json_normalize(veris_atk_map['veris_to_attack'], sep=".").to_dict(orient="records")[0]
        veris_atk = list(veris_atk.keys())
        veris_atk = [v[:-5] for v in veris_atk]
        veris_atk = [(v[:-6], v[-5:]) if v[-6] == "." else (v[:-10], v[-9:]) for v in veris_atk]
                    
        # Add veris -> attack
        for enum,k in veris_atk:
            enum = {
                "action.hacking.variety.HTTP Response Splitting": "action.hacking.variety.HTTP response splitting",
                "action.hacking.variety.Use of backdoor or C2": "action.hacking.vector.Backdoor",
                "action.hacking.vector.Backdoor or C2": "action.hacking.vector.Backdoor",
                "action.hacking.variety.Footprinting": "action.hacking.variety.Profile host"
            }.get(enum, enum) # fix some changes since the mapping
            if "variety" in enum:
                veris.add((self.veris_ns[quote(enum.split(".")[-1])], OWL.equivalentClass, atk_ns[k]))
            else:
                veris.add((self.eris_ns[quote("." + enum)], OWL.equivalentClass, atk_ns[k]))

        self.veris_graph = veris


schemafile = "/Users/v685573/Documents/Development/vzrisk/veris/verisc-merged.json"
labelsfile = "/Users/v685573/Documents/Development/vzrisk/veris/verisc-labels.json"
atk_map_file = "/Users/v685573/Documents/mitre/attack_to_veris/frameworks/veris/veris-mappings.json"
af_filename = "/Users/v685573/Documents/mitre/attack flow/attack_flow_0.2.6.owl"
veris_owl_file = "/Users/v685573/Documents/mitre/attack flow/veris.owl"
VERIS_NAMESPACE = "https://veriscommunity.net/attack-flow#"
ATK_NAMESPACE = "urn:absolute:attack#"
AF_NAMESPACE = "https://vz-risk.github.io/flow/attack-flow#"



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=descriptionText)
    parser.add_argument("-l","--log_level",choices=["critical","warning","info","debug"], help="Minimum logging level to display", default="info")
    parser.add_argument('--log_file', help='Location of log file', default=None)
    descriptionText = """This script creates an OWL VERIS schema from the VERIS 
schema file and labels file. Optionally, it can also add the attack flow schema
and the veris to Mitre att&ck (tm) mapptings."""
    parser.add_argument("--veris_ns", help="String representing the namespace for VERIS.", default="https://veriscommunity.net/attack-flow#")
    parser.add_argument("-m","--mergedfile", help="The fully merged json schema file.", required=True)
    parser.add_argument("--labels",
                        help="the labels file. (Normally '../verisc-labels.json'.", required=True) #, default=DEFAULTLABELS)
    parser.add_argument("-o", "--output",
                        help="the location to save the VERIS json-ld file. (Normally '../verisc-owl.json'.)", required=True) #, default=MERGED)
    parser.add_argument("--af", help="The filename of the Attack Flow graph file in json-ld format.", default="https://vz-risk.github.io/flow/attack-flow#")
    parser.add_argument("--af_ns", help="String representing the namespace for attack flow. (should match what's in the 'af' file.", default=None)
    parser.add_argument("--atk_map", help="The json file mapping between veris and att&ck.", default=None)
    parser.add_argument("--atk_ns", help="String representing the namespace for att&ck.", default=None)
    args = parser.parse_args()
    #args = {k:v for k,v in vars(args).items() if v is not None}

    logging.info("Setting up logging")
    if args.log_file:
        logging.basicConfig(level=args.log_level, filename=args.log_file) 
    else:
        logging.basicConfig(level=args.log_level) 

    with open(args.mergedfile, 'r') as filehandle:
        schema = json.load(filehandle)
    with open(args.labels, 'r') as filehandle:
        labels = json.load(filehandle)
    if args.atk_map:
        with open(args.atk_map, 'r') as filehandle:
            atk_map = json.load(filehandle)

    logging.info("Initialize the class.")
    veris_owl = veris2af(
        veris=args.mergedfile,
        veris_labels=args.labels,
        veris_namespace=args.veris_ns,
        attack_flow_namespace=args.af_ns
    )

    logging.info("Convert the schema.")
    veris_owl.veris_to_owl()

    if args.af:
        logging.info("Adding attack flow schema.")
        veris_owl.add_af(args.af)

    if args.atk_map:
        logging.info("Adding attack map schema.")
        veris_owl.veris_to_atk(args.atk_map)

    logging.info("Writting output.")
    with open(args.output, 'w') as filehandle:
        json.dump(filehandle, veris_owl.veris_graph.serialize(format="json-ld"))



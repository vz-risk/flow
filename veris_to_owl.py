### Imports ###
import jsonschema
import json
import argparse
import logging
import copy
import os
#import importlib
import imp
from collections import OrderedDict
from rdflib import Graph, Namespace
from rdflib.term import Literal, URIRef, _castPythonToLiteral
from rdflib.namespace import RDF, RDFS, OWL, XSD
import re
from urllib.parse import quote, unquote
import collections
import pandas as pd

### Constants ###
schemafile = "/Users/v685573/Documents/Development/vzrisk/veris/verisc-merged.json"
labelsfile = "/Users/v685573/Documents/Development/vzrisk/veris/verisc-labels.json"
atk_map_file = "/Users/v685573/Documents/mitre/attack_to_veris/frameworks/veris/veris-mappings.json"
af_filename = "/Users/v685573/Documents/mitre/attack flow/attack_flow_0.2.6.owl"
veris_owl_file = "/Users/v685573/Documents/mitre/attack flow/veris.owl"
NAMESPACE = "https://veriscommunity.net/attack-flow#"
ATK_NAMESPACE = "https://vz-risk.github.io/flow/attack-flow#" # "urn:absolute:attack#"
atk_ns = Namespace(ATK_NAMESPACE)


anchor_map = {
    "action": atk_ns["action"],
    "asset": atk_ns["asset"],
    "extra": atk_ns["property"]
} # default is to URIRef("urn:absolute:flow-v1#property")

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


### Functions ###
def deepGetAttr(od, name):
    if len(name) > 1:
        return deepGetAttr(od[name[0]], name[1:])
    else:
        return od[name[0]]

def veris_to_owl(d, lbl, name, g):
    #print(f"starting {name}")
    try:
        parent = name.split(".")[-2]
    except:
        parent = ""
    child = name.split(".")[-1]
    references = set(g.subjects()).union(g.objects()).union(g.predicates())
    try:
        # for objects we'll recurse into them
        if d['type'] == "object":
            lbl = lbl + "properties."
            # for most things create the parent-child paths
            if child != "" and child not in anchor_map: # don't include things that are mapped to other classes
                # If it's the root, link to properties
                if parent == "":
                    g.add((veris_ns[quote(child)], RDFS.subClassOf, atk_ns["property"]))
                # if the parent is an one of the special places to anchor, replace the parent with the anchor
                elif parent in anchor_map:
                    g.add((veris_ns[quote(child)], RDFS.subClassOf, anchor_map[parent]))
                # else link the parent and the child
                else:
                    g.add((veris_ns[quote(child)], RDFS.subClassOf, veris_ns[quote(parent)]))
                if 'description' in d:
                    g.add((veris_ns[quote(child)], RDFS.comment, Literal(d['description'])))
                # label the child
                g.add((veris_ns[quote(child)], RDFS.label, Literal(child)))
            # recurse into the properties
            for k, v in d['properties'].items():
                #print([k, v])
                veris_to_owl(v, lbl, name + "." + k, g)
        # If instead of an object it's an array, just recurse the items and treat them as strings, etc
        elif d['type'] == "array":
            lbl = lbl + "items."
            veris_to_owl(d['items'], lbl, name, g)
            #TODO: add the veris_ns[name] list as an object property of the main key (same or higher level)
        elif d['type'] in ["string", "number", "boolean", "integer"] or (d['type']): 
            # if the string doesn't have options, add it as a data property
            if 'enum' not in d: # literals
                # If it doesn't already exist, give it a type, mark it a Data Property, and give it a literal name. Then link it to it's parent
                if veris_ns[quote(child)] not in references:
                    g.add((veris_ns[quote(child)], RDF.type, OWL.DatatypeProperty))
                    g.add((veris_ns[quote(child)], RDFS.range, type_map[d['type']]))
                    g.add((veris_ns[quote(child)], RDFS.label, Literal(child)))
                    if 'description' in d:
                        g.add((veris_ns[quote(child)], RDFS.comment, Literal(d['description'])))
                # Link to the appropriate parent (top of namespace, anchor point, or parent)
                if parent == "":
                    g.add((veris_ns[quote(child)], RDFS.domain, atk_ns["attack-flow"]))
                elif parent in anchor_map:
                    g.add((veris_ns[quote(child)], RDFS.domain, anchor_map[parent]))
                else:
                    g.add((veris_ns[quote(child)], RDFS.domain, veris_ns[quote(parent)]))
            # if this is one of the main enumerations.
            elif child == "variety":
                for enum in d['enum']:
                    # Assets is special so we have to treat it special
                    if parent == "assets":
                        if enum != "Other" and enum != "Unknown": # because unknown/other don't start with a a letter representing the parent
                            g.add((veris_ns[quote(enum)], RDFS.subClassOf, veris_ns[quote(asset_map[enum[0]])]))
                            g.add((veris_ns[quote(enum)], RDFS.label, Literal(enum[4:])))
                    # In case we have to handle attribute differently since it's a list of objects...
#                    elif name.startswith(".attribute"):
#                        g.add((veris_ns[quote(enum)], RDFS.subPropertyOf, veris_ns[quote(parent)]))
#                        g.add((veris_ns[quote(enum)], RDFS.label, Literal(enum)))
                    # otherwise just connect the enumerations directly
                    else:
                        g.add((veris_ns[quote(enum)], RDFS.subClassOf, veris_ns[quote(parent)]))
                        g.add((veris_ns[quote(enum)], RDFS.label, Literal(enum)))
                    # try and get the definition from the labels file and add it as a comment. Otherwise, pass.
                    try:
                        value = deepGetAttr(labels, (name + "." + enum)[1:].split("."))
                        g.add((veris_ns[quote(enum)], RDFS.comment, Literal(value)))
                    except KeyError:
                        pass
            else: # non-main enumerations
                # create a thing with name + enum as a subclass of lists to store the enumerations
                # create a object property type of name+enum w/ subclass of 'lists' to point to the enumeration
                g.add((veris_ns[quote(name + "Enum")], RDFS.subClassOf, veris_ns['lists']))
                g.add((veris_ns[quote(name + "Enum")], RDFS.label, Literal(name)))
                g.add((veris_ns[quote(name)], RDF.type, OWL.ObjectProperty))
                g.add((veris_ns[quote(name)], RDFS.label, Literal(name)))
                if parent == "":
                    g.add((veris_ns[quote(name)], RDFS.domain, atk_ns["attack-flow"]))
                elif parent in anchor_map:
                    g.add((veris_ns[quote(name)], RDFS.domain, anchor_map[parent]))
                else:
                    g.add((veris_ns[quote(name)], RDFS.domain, veris_ns[quote(parent)]))
                g.add((veris_ns[quote(name)], RDFS.range, veris_ns[quote(name + "Enum")]))
                for enum in d['enum']:
                    # based on https://stackoverflow.com/questions/18785499/modelling-owl-datatype-property-restrictions-with-a-list-of-values
                    g.add((veris_ns[quote(name + "." + enum)], RDFS.subClassOf,veris_ns[quote(name + "Enum")]))
                    g.add((veris_ns[quote(name + "." + enum)], RDFS.label, Literal(enum)))
                    try:
                        value = deepGetAttr(labels, (name + "." + enum)[1:].split("."))
                        g.add((veris_ns[quote(name + "." + enum)], RDFS.comment, Literal(value)))
                    except KeyError:
                        pass
                if parent == "":
                    g.add((veris_ns[quote(child)], RDFS.domain, atk_ns["attack-flow"]))
                elif parent in anchor_map:
                    g.add((veris_ns[quote(child)], RDFS.domain, anchor_map[parent]))
                else:
                    g.add((veris_ns[quote(child)], RDFS.domain, veris_ns[quote(parent)]))

        else:
            logging.warning("json schema type 'null' not currently supported. d: {0}, lbl: {1}, name: {2}, parent: {3}".format(d, lbl, name, parent))
    except:
        print("d: {0}, lbl: {1}, name: {2}".format(d, lbl, name))
        raise
    return g



### Convert ###
veris_ns = Namespace(NAMESPACE)

# Open schema, labels, attack_to_veris mapping
with open(schemafile, 'r') as filehandle:
    schema = json.load(filehandle)
with open(labelsfile, 'r') as filehandle:
    labels = json.load(filehandle)
with open(atk_map_file, 'r') as filehandle:
    atk_map = json.load(filehandle)

# Start Graph
veris = Graph()
# veris.parse(af_filename) # do we _really_ want to add all of Att&ckflow or just what we need to add? Maybe an option?

# Add top level stuff
veris.add((veris_ns['lists'], RDFS.subClassOf, atk_ns["property"])) # list holder within properties
for asset in asset_map: # assets (since they aren't actually in VERIS)
    veris.add((veris_ns[quote(asset_map[asset])], RDFS.subClassOf, veris_ns['assets']))

# Convert VERIS to OWL
veris = veris_to_owl(schema, "", "", veris)

# Add ATT&CK Equivalence
# Add some basic att&ck stuff
veris.add((atk_ns['technique'], RDFS.subClassOf, atk_ns["action"]))
veris.add((atk_ns['name'], RDF.type, OWL.DatatypeProperty))
# Add attack -> Veris
for k, v in atk_map['attack_to_veris'].items():
    veris.add((atk_ns[k], RDFS.subClassOf, atk_ns['technique']))
    veris.add((atk_ns[k], atk_ns['name'], Literal(v['name'])))
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
            veris.add((atk_ns[k], OWL.equivalentClass, veris_ns[quote(enum.split(".")[-1])]))
        else:
            veris.add((atk_ns[k], OWL.equivalentClass, veris_ns[quote("." + enum)]))

# get the table fixed up. (It's kinda a mess the way it's created)
veris_to_atk = pd.json_normalize(atk_map['veris_to_attack'], sep=".").to_dict(orient="records")[0]
veris_to_atk = list(veris_to_atk.keys())
veris_to_atk = [v[:-5] for v in veris_to_atk]
veris_to_atk = [(v[:-6], v[-5:]) if v[-6] == "." else (v[:-10], v[-9:]) for v in veris_to_atk]
            
# Add veris -> attack
for enum,k in veris_to_atk:
    enum = {
        "action.hacking.variety.HTTP Response Splitting": "action.hacking.variety.HTTP response splitting",
        "action.hacking.variety.Use of backdoor or C2": "action.hacking.vector.Backdoor",
        "action.hacking.vector.Backdoor or C2": "action.hacking.vector.Backdoor",
        "action.hacking.variety.Footprinting": "action.hacking.variety.Profile host"
    }.get(enum, enum) # fix some changes since the mapping
    if "variety" in enum:
        veris.add((veris_ns[quote(enum.split(".")[-1])], OWL.equivalentClass, atk_ns[k]))
    else:
        veris.add((veris_ns[quote("." + enum)], OWL.equivalentClass, atk_ns[k]))

with open(veris_owl_file, 'w') as filehandle:
    filehandle.write(veris.serialize(format="xml"))

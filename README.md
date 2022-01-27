# flow
This repository contains tools and resources provided by the DBIR team for working with Attack Flow (https://github.com/center-for-threat-informed-defense/attack-flow). A joint project between the Mitre Center for Threat Informed Defense (CTID) and CTID participants including Verizon.

Attack Flow is a standard for non-atomic data in infosec.  Atomic data is single records. Non-atomic data is defined by three things: Complexity, Causality, and Context:
 * Complexity in that it can represent relationships between more than two things
 * Causality in that it can represent causal (directed) graphs including paths (sequences of individual actions and assets)
 * Context in that it can it can represent knowledge (whether it be an organization's structure, it's assets, threat intelligence, artifacts from a forensic investigation, or anything else)

This repository provides a few things not currentely available in the Attack Flow repository:
 * The Attack Flow Schema formatted as a graph and stored in JSON (specifically json-ld)
 * A python class to convert attack flow records between json-schema and json-ld (graph-based) attack flow
 * Documents on how to use existing tools to work with Attack Flow
   * Creating Flows # Probably that docker tool
   * Visualizing # Would be really nice to have a lincurious thing here but could use gephi or one of the onlien tools
   * Querying # a sparql database of some type

Additional resources can be found in the VERIS repository (Attack Flow version of VERIS and python class to convert VERIS JSON to Attack Flow JSON) and VCDB (Attack Flow representation of VCDB records where path data is available.)

As with any new project, the functionality is not complete nor perfect.  If you have any questions, please contact dbir@verizon.com.
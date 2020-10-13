# based on mitmdump raw output
# https://github.com/mitmproxy/mitmproxy/blob/v2.0.2/examples
# inspired and based on Jason Haddixs HUNT Burp Plugin Research @Jhaddix
# https://github.com/bugcrowd/HUNT

from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
import json
import template

# get identifiers from issues.json
issues = []
with open('issues.json', 'r') as f:
    issues = json.load(f)

# {'vuln name': ['identifier1', 'identifier2', ...}
vulnIdentifiers = {}
for issue in issues["issues"]:
    vulnIdentifiers[issue] = issues["issues"][issue]["params"]

# load dump and prepare flows
logfile = "dump.txt"
flows = []
try:
    logfile = open(logfile, "rb")
    freader = io.FlowReader(logfile)
    for f in freader.stream():
        flows.append(f)
except FlowReadException as e:
    print("Flow file corrupted: {}".format(e))
except IOError as e:
    print("Cant handle file: {}".format(e))

# TODO: why are there flows without request attribute?
# unpacking useful information from flows
# text = json blob as string
# [[url, query_fields, body_fields, text], ...]
preparedFlows = [
    [
        flow.request.pretty_url,
        list(flow.request.query.fields),
        list(flow.request.urlencoded_form.fields),
        flow.request.text   # encoding issues to with big json blops like spa
    ] for flow in flows if hasattr(flow, "request")
]

# identifying requests of interest
requestsOfInterest = []
for flow in preparedFlows:
    for vulnName, identifiers in vulnIdentifiers.items():
        for identifier in identifiers:
            for queryParam in flow[1]:
                # queryParam[0] = Key, queryParam[1] = Value
                # only check parameter name
                if identifier in queryParam[0].lower():
                    requestsOfInterest.append([flow[0], vulnName, identifier, queryParam])
                    # print("URL: {}\tVulnerability Class: {}\tIdentifier: {}\t, KV Pair:{}".format(flow[0], vulnName, identifier, queryParam))
            for bodyParam in flow[2]:
                # bodyParam[0] = Key, bodyParam[1] = Value
                # only check parameter name
                if identifier in bodyParam[0].lower():
                    requestsOfInterest.append([flow[0], vulnName, identifier, bodyParam])
                    # print("URL: {}\tVulnerability Class: {}\tIdentifier: {}\tKV Pair:{}".format(flow[0], vulnName, identifier, bodyParam))
            # for textParam in flow[3]:
            #     if identifier in textParam[0].lower():
            #         requestsOfInterest.append([flow[0], vulnName, identifier, textParam])
            # if identifier in flow[3]:
            #     requestsOfInterest.append([flow[0], vulnName, identifier, flow[3]])


templateBody = ""
for index, roi in enumerate(requestsOfInterest):
    templateBody += "<tr>"
    templateBody += "<th scope=\"row\">" + str(index + 1) + "</th>"
    templateBody += "<td>" + roi[1][0:50] + "</td>"
    templateBody += "<td>" + roi[2][0:50] + "</td>"
    templateBody += "<td>" + str(roi[3])[0:75] + "</td>"
    templateBody += "<td><button class=\"btn btn-primary\" type=\"button\" data-toggle=\"collapse\" data-target=\"#queryDetail-" + str(index) + "\" aria-expanded=\"false\" aria-controls=\"queryDetail-" + str(index) + "\">Details</button></td>"
    templateBody += "<td><a href=\"" + roi[0] + "\" target=\"blank\">" + roi[0] + "</a></td>"
    templateBody += "</tr>"

file = open("template0.html", "w+")
file.write(template.templateHeader + templateBody + template.templateFooter)
file.close()

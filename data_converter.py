import xmltodict 
import json 
import argparse
# method to generate json file
class GenerateJson():
    def convertXml(self, xml_file, xml_attribs=True):
        with open (xml_file, "rb") as f:
            d = xmltodict.parse(f, xml_attribs=xml_attribs)
            return d 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="path and name of input xml file")
    parser.add_argument("-o", "--output", help="path and name of output json file")
    args = parser.parse_args()
    gj = GenerateJson()
    data = gj.convertXml(args.input, True)
    with open(args.output, 'w') as jfile:
        json.dump (data, jfile, indent = 2)
    return 
if __name__ == "__main__":
    main()

#!/usr/bin/env python
# coding: utf-8

# In[18]:


# A script for making the MITRE coverage map for TH
# Current input: coverage map.xlsx
# Current output: output.json


import pprint
import json
import pandas as pd
import numpy as np
import seaborn as sns
import argparse

parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-T", "--TTP", help='''Input TTP Column Index.
                                            if None, the index of ttp_colname will be automatically determined.
                                            If index_ttp value is set, then its value will be used and
                                            ttp_colname is ignored''')

parser.add_argument("-D", "--Date", help = '''Date Flag, Default: automatic.
                                                if None, automatically color grade if 'Date' column is found.
                                                if False, never color grade.
                                                if True, do color grading''')

parser.add_argument("-I", "--Input", help = '''Path to the input file''')

# Read arguments from command line
args = parser.parse_args()

layer = {
    "name": "layer3",
    "versions": {
        "attack": "11",
        "navigator": "4.5.5",
        "layer": "4.3"},
    "domain": "enterprise-attack",
    "description": "",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Azure AD",
            "Office 365",
            "SaaS",
            "IaaS",
            "Google Workspace",
            "PRE",
            "Network",
            "Containers"]},
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": False,
        "showName": True,
        "showAggregateScores": False,
        "countUnscored": False},
    "hideDisabled": False,
    "techniques": [],
    "gradient": {  # Maybe this part is unnecessary
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False}

possubs = {'T1548': 4, 'T1134': 5, 'T1531': 0, 'T1087': 4, 'T1098': 5, 'T1583': 6, 'T1595': 3, 'T1557': 3,
           'T1071': 4, 'T1010': 0, 'T1560': 3, 'T1123': 0, 'T1119': 0, 'T1020': 1, 'T1197': 0, 'T1547': 15,
           'T1037': 5, 'T1217': 0, 'T1176': 0, 'T1185': 0, 'T1110': 4, 'T1612': 0, 'T1115': 0, 'T1580': 0,
           'T1538': 0, 'T1526': 0, 'T1619': 0, 'T1059': 8, 'T1092': 0, 'T1586': 2, 'T1554': 0, 'T1584': 6,
           'T1609': 0, 'T1613': 0, 'T1136': 3, 'T1543': 4, 'T1555': 5, 'T1485': 0, 'T1132': 2, 'T1486': 0,
           'T1530': 0, 'T1602': 2, 'T1213': 3, 'T1005': 0, 'T1039': 0, 'T1025': 0, 'T1565': 3, 'T1001': 3,
           'T1074': 2, 'T1030': 0, 'T1622': 0, 'T1491': 2, 'T1140': 0, 'T1610': 0, 'T1587': 4, 'T1006': 0,
           'T1561': 2, 'T1484': 2, 'T1482': 0, 'T1189': 0, 'T1568': 3, 'T1114': 3, 'T1573': 2, 'T1499': 4,
           'T1611': 0, 'T1585': 2, 'T1546': 15, 'T1480': 1, 'T1048': 3, 'T1041': 0, 'T1011': 1, 'T1052': 1,
           'T1567': 2, 'T1190': 0, 'T1203': 0, 'T1212': 0, 'T1211': 0, 'T1068': 0, 'T1210': 0, 'T1133': 0,
           'T1008': 0, 'T1083': 0, 'T1222': 2, 'T1495': 0, 'T1187': 0, 'T1606': 2, 'T1592': 4, 'T1589': 3,
           'T1590': 6, 'T1591': 4, 'T1615': 0, 'T1200': 0, 'T1564': 10, 'T1574': 13, 'T1562': 10, 'T1525': 0,
           'T1070': 6, 'T1202': 0, 'T1105': 0, 'T1490': 0, 'T1056': 4, 'T1559': 3, 'T1534': 0, 'T1570': 0,
           'T1036': 7, 'T1556': 5, 'T1578': 4, 'T1112': 0, 'T1601': 2, 'T1111': 0, 'T1621': 0, 'T1104': 0,
           'T1106': 0, 'T1599': 1, 'T1498': 2, 'T1046': 0, 'T1135': 0, 'T1040': 0, 'T1095': 0, 'T1571': 0,
           'T1027': 6, 'T1588': 6, 'T1137': 6, 'T1003': 8, 'T1201': 0, 'T1120': 0, 'T1069': 3, 'T1566': 3,
           'T1598': 3, 'T1647': 0, 'T1542': 5, 'T1057': 0, 'T1055': 15, 'T1572': 0, 'T1090': 4, 'T1012': 0,
           'T1620': 0, 'T1219': 0, 'T1563': 2, 'T1021': 6, 'T1018': 0, 'T1091': 0, 'T1496': 0, 'T1207': 0,
           'T1014': 0, 'T1053': 7, 'T1029': 0, 'T1113': 0, 'T1597': 2, 'T1596': 5, 'T1593': 2, 'T1594': 0,
           'T1505': 5, 'T1489': 0, 'T1129': 0, 'T1072': 0, 'T1518': 1, 'T1608': 5, 'T1528': 0, 'T1558': 4,
           'T1539': 0, 'T1553': 6, 'T1195': 3, 'T1218': 14, 'T1082': 0, 'T1614': 1, 'T1016': 1, 'T1049': 0,
           'T1033': 0, 'T1216': 1, 'T1007': 0, 'T1569': 2, 'T1529': 0, 'T1124': 0, 'T1080': 0, 'T1221': 0,
           'T1205': 1, 'T1537': 0, 'T1127': 1, 'T1199': 0, 'T1552': 7, 'T1535': 0, 'T1550': 4, 'T1204': 3,
           'T1078': 4, 'T1125': 0, 'T1497': 3, 'T1600': 2, 'T1102': 3, 'T1047': 0, 'T1220': 0}
techs = []
legend = []


def append_techs(ttp, color, weight='99'):
    layer['techniques'].append({"techniqueID": ttp,
                                # "tactic": "defense-evasion",
                                "color": color,  # + weight,
                                "comment": "",
                                "enabled": True,
                                "metadata": [],
                                "links": [],
                                "showSubtechniques": False})


def append_legend(color, date):
    layer['legendItems'].append({'label': date[:9],
                                 'color': color})


def set_gradient_state(state=False):
    """either ignores/removes gradient or adds it"""
    if not state:
        del layer['gradient']  ## <-- delete gradient state
        #layer['gradient'] = None  ## <-- or simply set it to none
    else:
        layer["gradient"] = {
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 100
    }

def create_json(filename, index_ttp= args.TTP, ttp_colname="TTP coverage", date_grade=args.Date):
    '''
       @params
       index_ttp : int or None, default : None
           the user_specified column index of ttp_colname.
           if None, the index of ttp_colname will be automatically determined.
           If index_ttp value is set, then its value will be used and
           ttp_colname is ignored

       @date_grade: boolean, None default : None
           whether to use the layer gradient or not.
           if None, automatically color grade if 'Date' column is found
           if False, never color grade
           if True, do color grading
       '''

    df = pd.read_excel(filename).iloc[::-1]

    if 'Index' not in df.columns:
      sheetname = 'Sheet2'
      df = pd.read_excel(filename, sheetname).iloc[::-1]
    else:
        df = pd.read_excel(filename, index_col=0).iloc[::-1]

    colnames = list(df.columns)

    interests = []

    if date_grade == 'True':
        date_grade = True
    elif date_grade == 'False':
        date_grade = False
    elif 'Date' not in colnames:
        date_grade = False
    else:
        date_grade = True
    set_gradient_state(date_grade)

    if 'Date' in colnames:
        interests.append('Date')

    indices = [colnames.index(interest) for interest in interests]
    if index_ttp is None:  # no exception handler here
        index_ttp = colnames.index(ttp_colname)
    else:
        index_ttp = int(index_ttp)

    indices.append(index_ttp)

    k = len(interests)
    df = df.iloc[:, indices]
    df = df[df.iloc[:, k].notna()]

    existing_ttp = []

    colors = sns.color_palette("coolwarm_r", len(df)).as_hex()

    for i in range(len(df)):
        ttps = str(df.iloc[i, k])
        ttps = [x.strip() for x in ttps.split(';')]
        subtechniques = {}

        for ttp in ttps:
            if not 'T' in ttp:
                ttp = 'T' + ttp

            if '.' in ttp:
                prefix, suffix = ttp.split('.')
                if prefix not in subtechniques.keys():
                    subtechniques[prefix] = [suffix]
                else:
                    subtechniques[prefix].append(suffix)
            else:
                subtechniques[ttp] = []

        for ttp, subs in subtechniques.items():
            if ttp not in existing_ttp:
                if subs == []:
                    append_techs(ttp, colors[i])
                else:
                    weight = len(subs) / possubs[ttp]
                    if weight == 1:
                        weight = '99'
                    else:
                        weight *= 100
                        weight = str(round(weight))

                    append_techs(ttp, colors[i], weight)

                    for ttp_sub in subs:
                        append_techs(ttp + '.' + ttp_sub, colors[i])

                existing_ttp.append(ttp)

        if str(df.iloc[i, 0]) != 'NaT':
            append_legend(colors[i], str(df.iloc[i, 0]))

    jsonFile = open("output.json", "w")
    jsonFile.write(json.dumps(layer))
    jsonFile.close()

    return layer


path = args.Input

create_json(path)

# In[ ]:





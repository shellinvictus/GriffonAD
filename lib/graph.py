import lib.consts as c
import dash
from dash import Dash, html, dcc, callback, Input, Output
import dash_cytoscape as cyto

# https://js.cytoscape.org/
# https://icon-sets.iconify.design/
# https://github.com/plotly/dash-cytoscape

# TODO
# - it would be nice with the navigator extension (https://codesandbox.io/p/sandbox/vanilla-h2cct?file=%2Fsrc%2Findex.js%3A115%2C24)
#  -> is it possible to add a cytoscape extension?


# Test to change dynamically the layout
# @callback(Output('canvas', 'layout'), Input('dropdown-update-layout', 'value'))
# def update_layout(layout):
    # return {
        # 'name': layout,
        # 'animate': True
    # }


class Graph():
    def __init__(self, db):
        self.db = db
        seen = set()
        self.elements = []
        for o in self.db.iter_users():
            self.object_generate_elements(o.sid, seen)


    def object_generate_elements(self, sid:str, seen:set):
        if sid in seen:
            return

        seen.add(sid)

        if sid not in self.db.objects_by_sid:
            self.elements.append({
                'data': {
                    'id': sid,
                    'label': sid
                }
            })
            return 

        o = self.db.objects_by_sid[sid]

        if o.type == c.T_GPO:
            classes = 'gpo'
        elif o.type == c.T_COMPUTER or o.type == c.T_DC:
            classes = 'computer'
        elif o.type == c.T_USER:
            classes = 'user'
        elif o.type == c.T_OU:
            classes = 'ou'
        elif o.type == c.T_GROUP:
            classes = 'group'
        elif o.type == c.T_DOMAIN:
            classes = 'domain'
        else:
            classes = ''

        if o.is_admin:
            name = '♦'
            classes += ' admin'
        elif o.can_admin:
            name = '★'
            classes += ' can_admin'
        else:
            name = ''

        if o.type == c.T_GPO:
            if o.bloodhound_json is None:
                name += o.original_name # only for fakedb
            else:
                name += o.bloodhound_json['Properties']['name'].upper()
        else:
            name += o.name.upper()

        if o.name.upper() in self.db.owned_db:
            classes += ' owned'

        self.elements.append({
            'data': {
                'id': sid,
                'label': name,
            },
            'classes': classes
        })

        for target_sid, rights in o.rights_by_sid.items():
            for r in rights:
                self.elements.append({
                    'data': {
                        'source': o.sid,
                        'target': target_sid,
                        'label': '+\n'.join(r.split('_'))
                    }
                })
            self.object_generate_elements(target_sid, seen)


    def run(self):
        app = Dash(title='Griffon')

        app.layout = html.Div([
            # dcc.Dropdown(
                # id='dropdown-update-layout',
                # value='cose',
                # clearable=False,
                # options=[
                    # {'label': name.capitalize(), 'value': name}
                    # for name in ['cose', 'breadthfirst']
                # ]
            # ),

            cyto.Cytoscape(
                id='canvas',
                boxSelectionEnabled=True,
                wheelSensitivity=0.3,
                responsive=True,
                layout={
                    'name': 'cose',
                    'nodeRepulsion': 100000,
                    # 'animate': False,
                },
                style={
                    'width': '100%',
                    'height': '100vh',
                },
                elements=self.elements,
                stylesheet=[
                    {
                        'selector': 'node',
                        'style': {
                            'content': 'data(label)',
                            'font-size': '12px',
                            'width': '30px',
                            'height': '30px',
                            'font-weight': 'bold',
                            'border-width': '4px',
                            'border-color': '#555',
                            'text-decoration-line': 'overline',
                            'background-color': '#999',
                        }
                    },
                    {
                        'selector': 'edge',
                        'style': {
                            'curve-style': 'bezier',
                            'content': 'data(label)',
                            'text-wrap': 'wrap',
                            'target-arrow-color': '#B7B7B7',
                            'target-arrow-shape': 'triangle',
                            'arrow-scale': .8,
                            'line-color': '#B7B7B7',
                            'font-size': '7px',
                            'width': '2px',
                            'height': '10px',
                            'edge-text-rotation': 'autorotate',
                        }
                    },
                    {
                        'selector': '.user',
                        'style': {
                            'background-color': '#97fa9a',
                            'border-color': '#48BA4B',
                            'background-image': dash.get_asset_url('user.svg'),
                            'background-size': 'cover',
                        },
                    },
                    {
                        'selector': '.computer',
                        'style': {
                            'background-color': '#F0BBA0',
                            'border-color': '#A66546',
                            'background-image': dash.get_asset_url('computer.svg'),
                        },
                    },
                    {
                        'selector': '.gpo',
                        'style': {
                            'background-color': '#908EDF',
                            'border-color': '#46448E',
                            'background-image': dash.get_asset_url('gpo.svg'),
                        },
                    },
                    {
                        'selector': '.group',
                        'style': {
                            'background-color': '#f1f5d8',
                            'border-color': '#848D49',
                            'background-image': dash.get_asset_url('group.svg'),
                        },
                    },
                    {
                        'selector': '.ou',
                        'style': {
                            'background-color': '#f1f5d8',
                            'border-color': '#848D49',
                            'background-image': dash.get_asset_url('group.svg'),
                        },
                    },
                    {
                        'selector': '.domain',
                        'style': {
                            'background-color': '#F83151',
                            'border-color': '#7E0014',
                            'background-image': dash.get_asset_url('domain.svg'),
                        },
                    },
                    {
                        'selector': '.admin',
                        'style': {
                            'color': '#FF0E00',
                        },
                    },
                    {
                        'selector': '.can_admin',
                        'style': {
                            'color': '#FFFC00',
                            'text-outline-color': '#000',
                            'text-outline-width': 2,
                        },
                    },
                    {
                        'selector': '.owned',
                        'style': {
                            'background-color': '#ddd',
                            'background-image': dash.get_asset_url('owned.svg'),
                        },
                    },
                    {
                        'selector': 'node:selected',
                        'style': {
                            'border-color': '#0067ff',
                        }
                    },
                    {
                        'selector': 'edge:selected',
                        'style': {
                            'line-color': '#0067ff',
                            'target-arrow-color': '#0067ff',
                        }
                    },
                ]
            )
        ])

        app.run(debug=True)

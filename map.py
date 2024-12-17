import csv
from typing import Dict
from pathlib import Path
import os

def get_sddl_mindmap_data() -> dict:
    """Returns the SDDL mindmap data structure for D3.js"""
    # Load CSV data
    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(current_dir, 'accessenums.csv')
    csv_data = parse_csv(csv_path)
    
    # Create rights nodes from CSV data
    rights_nodes = []
    seen_rights = set()
    
    for row in csv_data.items():
        name = row[0].split(' - ')[0]  # Get just the name part
        if name not in seen_rights:
            seen_rights.add(name)
            rights_nodes.append({
                "name": f"{name}",
                "description": row[1]['description'],
                "link": row[1]['link']
            })

    # Example of a node with table data
    table_node = {
        "name": "Resource Attribute Types",
        "tableData": {
            "headers": ["Code", "Description"],
            "rows": [
                ["TI", "Signed Integer"],
                ["TU", "Unsigned Integer"],
                ["TS", "Wide String"],
                ["TD", "SID"],
                ["TX", "Octet String"],
                ["TB", "Boolean"]
            ]
        }
    }

    return {
        "name": "SDDL Demystified",
        "children": [
            {
                "name": "Owner (O)",
                "description": "Defines the owner of the object",
                "children": [
                    {"name": "BA - Built-in Administrators"},
                    {"name": "SY - System"},
                    {"name": "DA - Domain Admins"},
                    {"name": "DU - Domain Users"},
                    {"name": "AO - Account Operators"},
                    {"name": "SO - Server Operators"},
                    {"name": "PO - Printer Operators"},
                    {"name": "BU - Built-in Users"},
                    {"name": "EA - Enterprise Admins"}
                ]
            },
            {
                "name": "Group (G)",
                "description": "Group that owns the object",
                "children": [
                    {"name": "BA - Built-in Administrators"},
                    {"name": "SY - System"},
                    {"name": "AU - Authenticated Users"},
                    {"name": "WD - Everyone"},
                    {"name": "PA - Personal Admin"},
                    {"name": "CO - Creator Owner"},
                    {"name": "CG - Creator Group"},
                    {"name": "BU - Built-in Users"},
                    {"name": "DU - Domain Users"}
                ]
            },
            {
                "name": "DACL (D)",
                "description": "Discretionary Access Control List",
                "children": [
                    {
                        "name": "ACE Types (Access Control Entries)",
                        "children": [
                            {"name": "A - Allow Access", "color": "#00ff00"},
                            {"name": "D - Deny Access", "color": "#ff0000"},
                            {"name": "OA - Object Allow"},
                            {"name": "OD - Object Deny"},
                            {"name": "AU - Audit"},
                            {"name": "AL - Alarm"}
                        ]
                    },
                    {
                        "name": "ACE Structure",
                        "children": [
                            {
                                "name": "Type",
                                "children": [
                                    {"name": "A - Access Allowed"},
                                    {"name": "D - Access Denied"}
                                ]
                            },
                            {
                                "name": "Flags",
                                "children": [
                                    {"name": "CI - Container Inherit"},
                                    {"name": "OI - Object Inherit"},
                                    {"name": "IO - Inherit Only"},
                                    {"name": "NP - No Propagate"},
                                    {"name": "ID - Inherited"},
                                    {"name": "SA - Successful Access Audit"},
                                    {"name": "FA - Failed Access Audit"}
                                ]
                            },
                            {
                                "name": "Rights",
                                "children": rights_nodes  # Use the dynamically generated rights nodes
                            }
                        ]
                    }
                ]
            },
            {
                "name": "SACL (S)",
                "description": "System Access Control List",
                "children": [
                    {
                        "name": "generic ace",
                        "description": "Standard access control entry",
                        "children": [
                            {
                                "name": "[ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid]",
                                "description": "Format of generic ACE entry",
                                "children": [
                                    {
                                        "name": "ace_type",
                                        "description": "Defines the type of ACE (audit, allow, deny)"
                                    },
                                    {
                                        "name": "ace_flags",
                                        "description": "Control inheritance and propagation"
                                    },
                                    {
                                        "name": "access_rights",
                                        "description": "Specific permissions granted or denied"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "name": "conditional ace",
                        "description": "ACE with additional conditions",
                        "children": [
                            {
                                "name": "[ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;resource_attribute]",
                                "description": "Format of conditional ACE entry"
                            }
                        ]
                    },
                    {
                        "name": "resource attribute ace",
                        "description": "ACE containing resource attributes",
                        "children": [
                            {
                                "name": "Resource Attribute Types",
                                "tableData": {
                                    "headers": ["Code", "Description"],
                                    "rows": [
                                        ["TI", "Signed Integer"],
                                        ["TU", "Unsigned Integer"],
                                        ["TS", "Wide String"],
                                        ["TD", "SID"],
                                        ["TX", "Octet String"],
                                        ["TB", "Boolean"]
                                    ]
                                }
                            }
                        ]
                    },
                    {
                        "name": "central policy ace",
                        "description": "ACE defined by central access policies"
                    }
                ]
            }
        ]
    }

def parse_csv(file_path: str) -> Dict[str, Dict[str, str]]:
    """Parses the access enums CSV file and returns a dictionary mapping names to their details"""
    data = {}
    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = f"{row['Name']} - {row['Value']}"
            data[key] = {
                'description': row['Description'],
                'details': row['Details'],
                'link': row['Link']
            }
    return data

def get_d3_mindmap_html() -> str:
    """Returns the HTML/JavaScript code for D3.js mindmap with enhanced hover functionality"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <style>
            .node circle {
                fill: #fff;
                stroke: #4f8ff0;
                stroke-width: 2px;
            }
            .node text {
                font: 14px sans-serif;
                fill: #fff;
            }
            .link {
                fill: none;
                stroke: #4f8ff0;
                stroke-width: 1.5px;
                opacity: 0.7;
            }
            body {
                background-color: #1E1E1E;
                margin: 0;
                padding: 0;
            }
            .node.highlight circle {
                stroke: #ff9900;
                stroke-width: 3px;
            }
            .node.ace-type circle {
                stroke: #00ff00;
            }
            .node:hover circle {
                stroke-width: 4px;
                cursor: pointer;
            }
            .node:hover text {
                font-weight: bold;
            }
            .tooltip {
                position: absolute;
                text-align: left;
                width: 300px;
                padding: 12px;
                font: 14px sans-serif;
                background: rgba(70, 130, 180, 0.9);
                border: 0px;
                border-radius: 8px;
                pointer-events: none;
                color: white;
            }
            .tooltip .title {
                font-weight: bold;
                margin-bottom: 8px;
            }
            .tooltip .description {
                margin-bottom: 8px;
            }
            .tooltip .link {
                color: #add8e6;
            }
            /* Add styles for collapsed nodes */
            .node--collapsed circle {
                fill: lightsteelblue;
            }
            /* Add table styles */
            .node-table {
                fill: #1E1E1E;
                stroke: #4f8ff0;
                stroke-width: 1px;
            }
            .table-row text {
                font: 12px sans-serif;
                fill: #fff;
            }
            .table-header {
                font-weight: bold;
                fill: #4f8ff0;
            }
            .table-cell {
                fill: none;
                stroke: #4f8ff0;
                stroke-width: 1px;
            }
        </style>
    </head>
    <body>
        <div id="tree-container"></div>
        <script>
            const inputData = %s;
            
            // Set the dimensions and margins
            const margin = {top: 20, right: 120, bottom: 20, left: 120},
                width = 1800 - margin.left - margin.right,
                height = 1000 - margin.top - margin.bottom;

            // Create the SVG container
            const svg = d3.select("#tree-container")
                .append("svg")
                .attr("width", width + margin.left + margin.right)
                .attr("height", height + margin.top + margin.bottom)
                .append("g")
                .attr("transform", `translate(${margin.left},${margin.top})`);

            // Declare the tree layout
            const tree = d3.tree()
                .size([height, width - 200])
                .separation((a, b) => (a.parent == b.parent ? 1 : 1.2));

            // Convert the data to D3's hierarchy structure
            const root = d3.hierarchy(inputData);
            
            // Collapse all nodes except root initially
            root.descendants().forEach(d => {
                if (d.depth > 0) {
                    d._children = d.children;
                    d.children = null;
                }
            });

            function createTable(selection, data) {
                const cellHeight = 20;
                const cellPadding = 10;
                const tableData = data.tableData;
                
                if (!tableData) return;

                // Calculate column widths based on content
                const columnWidths = tableData.headers.map(header => {
                    const headerWidth = header.length * 8;  // Approximate width based on text length
                    const contentWidths = tableData.rows.map(row => 
                        row[tableData.headers.indexOf(header)].length * 8
                    );
                    return Math.max(headerWidth, ...contentWidths) + cellPadding * 2;
                });

                const tableWidth = columnWidths.reduce((a, b) => a + b, 0);
                const tableHeight = (tableData.rows.length + 1) * cellHeight;

                // Create table background
                selection.append("rect")
                    .attr("class", "node-table")
                    .attr("x", -tableWidth / 2)
                    .attr("y", -tableHeight / 2)
                    .attr("width", tableWidth)
                    .attr("height", tableHeight);

                // Create header
                const header = selection.append("g")
                    .attr("class", "table-header");

                let xPos = -tableWidth / 2;
                tableData.headers.forEach((h, i) => {
                    // Header cell background
                    header.append("rect")
                        .attr("class", "table-cell")
                        .attr("x", xPos)
                        .attr("y", -tableHeight / 2)
                        .attr("width", columnWidths[i])
                        .attr("height", cellHeight);

                    // Header text
                    header.append("text")
                        .attr("x", xPos + columnWidths[i] / 2)
                        .attr("y", -tableHeight / 2 + cellHeight / 2)
                        .attr("dy", ".35em")
                        .attr("text-anchor", "middle")
                        .text(h);

                    xPos += columnWidths[i];
                });

                // Create rows
                tableData.rows.forEach((row, rowIndex) => {
                    const y = -tableHeight / 2 + (rowIndex + 1) * cellHeight;
                    let xPos = -tableWidth / 2;

                    row.forEach((cell, colIndex) => {
                        // Cell background
                        selection.append("rect")
                            .attr("class", "table-cell")
                            .attr("x", xPos)
                            .attr("y", y)
                            .attr("width", columnWidths[colIndex])
                            .attr("height", cellHeight);

                        // Cell text
                        selection.append("text")
                            .attr("class", "table-row")
                            .attr("x", xPos + columnWidths[colIndex] / 2)
                            .attr("y", y + cellHeight / 2)
                            .attr("dy", ".35em")
                            .attr("text-anchor", "middle")
                            .text(cell);

                        xPos += columnWidths[colIndex];
                    });
                });
            }

            function updateNode(nodeEnter) {
                // For regular nodes
                nodeEnter.filter(d => !d.data.tableData)
                    .append("circle")
                    .attr("r", 8)
                    .style("fill", d => d._children ? "lightsteelblue" : "#fff");

                // For table nodes
                nodeEnter.filter(d => d.data.tableData)
                    .each(function(d) {
                        createTable(d3.select(this), d.data);
                    });

                // Add labels (only for non-table nodes)
                nodeEnter.filter(d => !d.data.tableData)
                    .append("text")
                    .attr("dy", ".35em")
                    .attr("x", d => d.children || d._children ? -13 : 13)
                    .attr("text-anchor", d => d.children || d._children ? "end" : "start")
                    .text(d => d.data.name);
            }

            // Function to update the tree visualization
            function update(source) {
                // Assigns the x and y position for the nodes
                const nodes = tree(root);

                // Update the nodes
                const node = svg.selectAll(".node")
                    .data(root.descendants(), d => d.data.name);

                // Enter new nodes
                const nodeEnter = node.enter()
                    .append("g")
                    .attr("class", "node")
                    .attr("transform", d => `translate(${source.y0 || source.y},${source.x0 || source.x})`)
                    .on("click", (event, d) => {
                        // Toggle children on click
                        if (d.children) {
                            d._children = d.children;
                            d.children = null;
                        } else {
                            d.children = d._children;
                            d._children = null;
                        }
                        update(d);
                    });

                updateNode(nodeEnter);

                // Update the node attributes and style
                const nodeUpdate = nodeEnter.merge(node);

                nodeUpdate.transition()
                    .duration(750)
                    .attr("transform", d => `translate(${d.y},${d.x})`);

                nodeUpdate.select("circle")
                    .attr("r", 8)
                    .style("fill", d => d._children ? "lightsteelblue" : "#fff");

                // Remove any exiting nodes
                const nodeExit = node.exit()
                    .transition()
                    .duration(750)
                    .attr("transform", d => `translate(${source.y},${source.x})`)
                    .remove();

                // Update the links
                const link = svg.selectAll(".link")
                    .data(root.links(), d => d.target.data.name);

                // Enter any new links at parent's previous position
                const linkEnter = link.enter()
                    .insert("path", "g")
                    .attr("class", "link")
                    .attr("d", d => {
                        const o = {
                            x: source.x0 || source.x,
                            y: source.y0 || source.y
                        };
                        return d3.linkHorizontal()
                            .x(d => d.y)
                            .y(d => d.x)
                            ({source: o, target: o});
                    });

                // UPDATE
                const linkUpdate = linkEnter.merge(link);

                // Transition back to the parent element position
                linkUpdate.transition()
                    .duration(750)
                    .attr("d", d3.linkHorizontal()
                        .x(d => d.y)
                        .y(d => d.x));

                // Remove any exiting links
                const linkExit = link.exit().transition()
                    .duration(750)
                    .attr("d", d => {
                        const o = {
                            x: source.x,
                            y: source.y
                        };
                        return d3.linkHorizontal()
                            .x(d => d.y)
                            .y(d => d.x)
                            ({source: o, target: o});
                    })
                    .remove();

                // Store the old positions for transition
                root.descendants().forEach(d => {
                    d.x0 = d.x;
                    d.y0 = d.y;
                });
            }

            // Initialize the display
            root.x0 = height / 2;
            root.y0 = 0;
            update(root);

            // Add tooltip functionality
            const tooltip = d3.select("body").append("div")
                .attr("class", "tooltip")
                .style("opacity", 0);

            svg.selectAll(".node")
                .on("mouseover", function(event, d) {
                    tooltip.transition()
                        .duration(200)
                        .style("opacity", .9);
                    
                    let tooltipContent = `<div class="title">${d.data.name}</div>`;
                    if (d.data.description) {
                        tooltipContent += `<div class="description">${d.data.description}</div>`;
                    }
                    if (d.data.link) {
                        tooltipContent += `<a class="link" href="${d.data.link}" target="_blank">Documentation</a>`;
                    }
                    
                    tooltip.html(tooltipContent)
                        .style("left", (event.pageX + 5) + "px")
                        .style("top", (event.pageY - 28) + "px");
                })
                .on("mouseout", function() {
                    tooltip.transition()
                        .duration(500)
                        .style("opacity", 0);
                });
        </script>
    </body>
    </html>
    """

def get_mindmap_examples() -> Dict[str, str]:
    """Returns common SDDL examples with explanations"""
    return {
        "basic_file": """
# Basic File Permission
## O:BAG:SYD:(A;;FA;;;BA)
- Owner: Built-in Administrators
- Group: System
- Full Access to Admins
""",
        "folder_inheritance": """
# Folder with Inheritance
## O:BAG:BAD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)
- Inherits to subfolders
- Propagates to files
- Full access for Admins and System
""",
        "restricted_access": """
# Restricted Access
## O:BAG:SYD:(A;;GR;;;AU)(D;;WD;;;WD)
- Read-only for authenticated users
- Denies write to everyone
- Protected system file pattern
"""
    }

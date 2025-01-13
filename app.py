import streamlit as st
import re
from typing import Dict, List, Tuple, Any
import sys
import os
from streamlit_markmap import markmap
from map import get_sddl_mindmap_data, get_d3_mindmap_html
import streamlit.components.v1 as components
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from sddl import (
        ACE_TYPES,
        ACE_FLAGS,
        RIGHTS,
        TRUSTEES,
        SDDL_EXAMPLES,
        WELL_KNOWN_SIDS,
        get_flag_description,
        get_right_description,
        get_trustee_description,
        get_access_details,
        generate_sddl_summary,
        parse_ace,
        format_ace_details,
        get_ace_display_data,
        get_access_type_description,
        parse_rights,
        CONTEXT_PERMISSIONS,
        parse_sddl
    )
except ImportError as e:
    st.error(f"Failed to import SDDL components: {str(e)}")
    st.stop()

def explain_sddl_section(tag: str, content: str) -> str:
    """Explains what each SDDL section means with expanded descriptions"""
    explanations = {
        'O': 'Owner',
        'G': 'Primary Group',
        'D': 'DACL (Discretionary Access Control List)',
        'S': 'SACL (System Access Control List)'
    }
    
    if tag in explanations:
        if tag in ['O', 'G']:
            trustee_name = TRUSTEES.get(content, content)
            trustee_desc = get_trustee_description(content)
            return f"{explanations[tag]}: {trustee_name}\n*{trustee_desc}*"
        return f"{explanations[tag]}: {content}"
    else:
        return f"Unknown tag: {tag}"

def process_acl(content: str, acl_type: str):
    """
    Process ACL content and display in expandable sections.

    Args:
        content: The ACL content string.
        acl_type: The type of ACL ('DACL' or 'SACL').
    """
    aces = [ace.strip() for ace in content.split(')') if ace.strip()]
    aces = [f"{ace})" for ace in aces]

    for ace_str in aces:
        if ace_str.strip('()'):
            ace_data = get_ace_display_data(ace_str)
            
            if 'error' in ace_data:
                st.error(f"⚠️ Error in ACE - {ace_str}: {ace_data['error']}")
                continue

            ace_type = "Allow" if ace_data['what'].startswith("ACCESS_ALLOWED") else "Deny" if ace_data['what'].startswith("ACCESS_DENIED") else ace_data['what']
            original_ace = ace_str.strip('()')
            expander_title = f"📋 {ace_type} - {ace_data['who']} - {original_ace}"

            with st.expander(expander_title):
                col1, col2 = st.columns([1, 2])

                with col1:
                    st.write("**Who:**")
                    st.write(ace_data['who'])
                    who_details = ace_data.get('who_details', 'No additional details available')
                    st.write(f"*{who_details}*")

                    st.write("**What:**")
                    st.write(ace_data['what'])
                    what_details = ace_data.get('what_details', 'No additional details available')
                    st.write(f"*{what_details}*")

                with col2:
                    st.write("**Permissions:**")
                    for right in ace_data['permissions']:
                        st.write(f"✓ {right['name']}")
                        st.write(f"  *{right['description']}*")

                if ace_data['special_conditions']:
                    st.write("**Special Conditions:**")
                    for flag in ace_data['special_conditions']:
                        flag_code = next((k for k, v in ACE_FLAGS.items() if v == flag['name']), None)
                        flag_desc = get_flag_description(flag_code) if flag_code else flag.get('description', 'No description available')
                        st.write(f"⚡ {flag['name']}")
                        st.write(f"  *{flag_desc}*")

def clear_selections():
    """Clears all selections in the SDDL builder."""
    st.session_state.selected_owner = None
    st.session_state.selected_group = None
    st.session_state.dacl_selections = []
    st.session_state.sacl_selections = []
    st.session_state.edit_dacl_index = None
    st.session_state.edit_sacl_index = None

def explain_generated_sddl(sddl_string: str):
    """Generates and displays a summary of the generated SDDL string."""
    summary = generate_sddl_summary(sddl_string)
    st.markdown(f"**Owner:** {summary['owner']}")
    st.markdown(f"**Group:** {summary['group']}")
    st.markdown("**Permissions:**")
    for permission in summary['permissions']:
        st.markdown(permission)
    st.markdown(f"**Impact:** {summary['impact']}")

def generate_sddl_from_selections():
    """Generates an SDDL string based on current selections."""
    owner_part = f"O:{st.session_state.selected_owner}" if st.session_state.selected_owner else ""
    group_part = f"G:{st.session_state.selected_group}" if st.session_state.selected_group else ""

    dacl_part = ""
    if st.session_state.dacl_selections:
        dacl_part = "D:" + "".join(
            f"({ace['type']};{ace['flags']};{ace['rights']};{ace['object_guid']};{ace['inherit_object_guid']};{ace['trustee']})"
            for ace in st.session_state.dacl_selections
        )

    sacl_part = ""
    if st.session_state.sacl_selections:
        sacl_part = "S:" + "".join(
            f"({ace['type']};{ace['flags']};{ace['rights']};{ace['object_guid']};{ace['inherit_object_guid']};{ace['trustee']})"
            for ace in st.session_state.sacl_selections
        )

    return owner_part + group_part + dacl_part + sacl_part

def build_sddl():
    """Builds the SDDL string based on user selections."""
    st.header("SDDL Builder")

    sddl_types = [
        "FileSystemRights",
        "RegistryRights", 
        "ActiveDirectoryRights",
        "GenericRights"
    ]
    selected_type = st.selectbox(
        "SDDL Context Type",
        options=sddl_types,
        help="Select the type of resource this SDDL will be applied to"
    )
    st.session_state.sddl_type = selected_type

    st.subheader("Owner")
    trustee_options = [""] + [f"{code} - {TRUSTEES[code]}" for code in TRUSTEES.keys()]
    selected_owner_full = st.selectbox("Select Owner", options=trustee_options)
    if selected_owner_full:
        selected_owner = selected_owner_full.split(" - ")[0] if selected_owner_full else ""
        st.session_state.selected_owner = selected_owner

    st.subheader("Group")
    selected_group_full = st.selectbox("Select Group", options=trustee_options)
    if selected_group_full:
        selected_group = selected_group_full.split(" - ")[0] if selected_group_full else ""
        st.session_state.selected_group = selected_group

    for acl_type in ["DACL", "SACL"]:
        st.subheader(f"{acl_type} ACEs")
        acl_key = f"{acl_type.lower()}_selections"

        if acl_key not in st.session_state:
            st.session_state[acl_key] = []

        edit_key = f"edit_{acl_type.lower()}_index"
        if edit_key not in st.session_state:
            st.session_state[edit_key] = None

        for i, ace in enumerate(st.session_state[acl_key]):
            ace_str = f"({ace['type']};{ace['flags']};{ace['rights']};{ace['object_guid']};{ace['inherit_object_guid']};{ace['trustee']})"
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.write(ace_str)
            with col2:
                if st.button(f"Edit", key=f"edit_{acl_type.lower()}_{i}"):
                    st.session_state[edit_key] = i
                    st.session_state[f"ace_type_{acl_type.lower()}"] = ace['type']
                    st.session_state[f"ace_flags_{acl_type.lower()}"] = list(ace['flags'])
                    st.session_state[f"ace_rights_{acl_type.lower()}"] = list(ace['rights'])
                    st.session_state[f"ace_object_guid_{acl_type.lower()}"] = ace['object_guid']
                    st.session_state[f"ace_inherit_object_guid_{acl_type.lower()}"] = ace['inherit_object_guid']
                    st.session_state[f"ace_trustee_{acl_type.lower()}"] = ace['trustee']
            with col3:
                if st.button(f"Delete", key=f"delete_{acl_type.lower()}_{i}"):
                    del st.session_state[acl_key][i]
                    if st.session_state[edit_key] == i:
                        st.session_state[edit_key] = None
                    st.rerun()

        is_edit_mode = st.session_state[edit_key] is not None
        edit_index = st.session_state[edit_key]

        form_key = f"{acl_type.lower()}_ace_form_{edit_index if is_edit_mode else 'new'}"

        with st.form(key=form_key):
            ace_type_options = [f"{code} - {description}" for code, description in ACE_TYPES.items()]
            ace_type_full = st.selectbox(
                "Type", 
                options=ace_type_options,
                key=f"ace_type_{acl_type.lower()}", 
                index=0 if not is_edit_mode else ace_type_options.index(f"{st.session_state[f'ace_type_{acl_type.lower()}']} - {ACE_TYPES[st.session_state[f'ace_type_{acl_type.lower()}']]}")
            )
            ace_type = ace_type_full.split(" - ")[0] if ace_type_full else ""

            ace_flags = st.multiselect(
                "Flags", 
                options=[f"{code} - {description}" for code, description in ACE_FLAGS.items()],
                key=f"ace_flags_{acl_type.lower()}", 
                default=[f"{flag} - {ACE_FLAGS[flag]}" for flag in (st.session_state[f"ace_flags_{acl_type.lower()}"] if is_edit_mode else [])]
            )
            ace_flags = [flag.split(" - ")[0] for flag in ace_flags]

            ace_rights = st.multiselect(
                "Rights", 
                options=[f"{code} - {description}" for code, description in RIGHTS.items()],
                key=f"ace_rights_{acl_type.lower()}", 
                default=[f"{right} - {RIGHTS[right]}" for right in (st.session_state[f"ace_rights_{acl_type.lower()}"] if is_edit_mode else [])],
                help=f"Select permissions specific to {st.session_state.sddl_type}"
            )
            ace_rights = [right.split(" - ")[0] for right in ace_rights]

            ace_object_guid = st.text_input(
                "Object GUID", 
                key=f"ace_object_guid_{acl_type.lower()}", 
                value=st.session_state[f"ace_object_guid_{acl_type.lower()}"] if is_edit_mode else ""
            )
            
            ace_inherit_object_guid = st.text_input(
                "Inherit Object GUID", 
                key=f"ace_inherit_object_guid_{acl_type.lower()}", 
                value=st.session_state[f"ace_inherit_object_guid_{acl_type.lower()}"] if is_edit_mode else ""
            )

            ace_trustee_options = [f"{code} - {description}" for code, description in TRUSTEES.items()]
            ace_trustee_full = st.selectbox(
                "Trustee", 
                options=ace_trustee_options,
                key=f"ace_trustee_{acl_type.lower()}", 
                index=0 if not is_edit_mode else ace_trustee_options.index(f"{st.session_state[f'ace_trustee_{acl_type.lower()}']} - {TRUSTEES[st.session_state[f'ace_trustee_{acl_type.lower()}']]}")
            )
            ace_trustee = ace_trustee_full.split(" - ")[0] if ace_trustee_full else ""

            submit_button = st.form_submit_button(label="Add/Update ACE")
            if submit_button:
                new_ace = {
                    'type': ace_type,
                    'flags': "".join(ace_flags),
                    'rights': "".join(ace_rights),
                    'object_guid': ace_object_guid,
                    'inherit_object_guid': ace_inherit_object_guid,
                    'trustee': ace_trustee
                }

                if is_edit_mode:
                    st.session_state[acl_key][edit_index] = new_ace
                    st.session_state[edit_key] = None
                else:
                    st.session_state[acl_key].append(new_ace)

                del st.session_state[f"ace_type_{acl_type.lower()}"]
                del st.session_state[f"ace_flags_{acl_type.lower()}"]
                del st.session_state[f"ace_rights_{acl_type.lower()}"]
                del st.session_state[f"ace_object_guid_{acl_type.lower()}"]
                del st.session_state[f"ace_inherit_object_guid_{acl_type.lower()}"]
                del st.session_state[f"ace_trustee_{acl_type.lower()}"]

                st.rerun()

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Generate SDDL"):
            sddl_string = generate_sddl_from_selections()
            
            st.markdown("### 📝 Generated SDDL")
            st.code(sddl_string, language="text")
            
            st.markdown("### 🔍 SDDL Breakdown")
            summary = generate_sddl_summary(sddl_string)
            parsed_sddl = parse_sddl(sddl_string)
            
            if 'O' in parsed_sddl:
                st.markdown("**👤 Owner**")
                owner_sid = parsed_sddl['O']
                owner_name = TRUSTEES.get(owner_sid, owner_sid)
                owner_desc = get_trustee_description(owner_sid)
                st.write(f"**Name:** {owner_name}")
                st.write(f"**Description:** {owner_desc}")
                st.write(f"**SID/Code:** `{owner_sid}`")
            
            if 'G' in parsed_sddl:
                st.markdown("**👥 Primary Group**")
                group_sid = parsed_sddl['G']
                group_name = TRUSTEES.get(group_sid, group_sid)
                group_desc = get_trustee_description(group_sid)
                st.write(f"**Name:** {group_name}")
                st.write(f"**Description:** {group_desc}")
                st.write(f"**SID/Code:** `{group_sid}`")
            
            if 'D' in parsed_sddl:
                display_acl("DACL", parsed_sddl['D'])
            
            if 'S' in parsed_sddl:
                display_acl("SACL", parsed_sddl['S'])
            
            st.markdown("### 📊 Security Impact Analysis")
            st.write(summary['impact'])
            
            st.markdown("### 💡 Similar Examples")
            for name, example in SDDL_EXAMPLES.items():
                if any(part in example['sddl'] for part in sddl_string.split(':')):
                    with st.expander(f"Example: {name}"):
                        st.code(example['sddl'], language="text")
                        st.write(example['description'])

    with col2:
        if st.button("Clear Selections"):
            clear_selections()

def main():
    """Main function to run the Streamlit app."""
    st.set_page_config(page_title="SDDL Parser", layout="wide")

    if "selected_owner" not in st.session_state:
        st.session_state.selected_owner = None
    if "selected_group" not in st.session_state:
        st.session_state.selected_group = None
    if "selected_type" not in st.session_state:
        st.session_state.selected_type = None
    if "dacl_selections" not in st.session_state:
        st.session_state.dacl_selections = []
    if "sacl_selections" not in st.session_state:
        st.session_state.sacl_selections = []

    st.title("The SDDLMaker")

    tab1, tab2, tab3, tab4 = st.tabs(["Parser", "Builder", "Reference", "Mindmap"])

    with tab1:
        st.header("Parse SDDL")
        sddl_input = st.text_area("Enter SDDL string", height=150)

        if st.button("Parse"):
            parsed_sddl = parse_sddl(sddl_input)
            if parsed_sddl:
                st.markdown("### 📝 Complete SDDL String")
                st.text_area(
                    "Raw SDDL",
                    value=sddl_input,
                    height=100,
                    disabled=True
                )

                col1, col2 = st.columns(2)
                with col1:
                    if 'O' in parsed_sddl:
                        st.markdown("### 👤 Owner")
                        owner_sid = parsed_sddl['O']
                        st.write(f"**SID:** {owner_sid}")
                        st.write(f"**Name:** {TRUSTEES.get(owner_sid, owner_sid)}")
                        st.write(f"**Description:** {get_trustee_description(owner_sid)}")
                
                with col2:
                    if 'G' in parsed_sddl:
                        st.markdown("### 👥 Primary Group")
                        group_sid = parsed_sddl['G']
                        st.write(f"**SID:** {group_sid}")
                        st.write(f"**Name:** {TRUSTEES.get(group_sid, group_sid)}")
                        st.write(f"**Description:** {get_trustee_description(group_sid)}")

                if 'D' in parsed_sddl:
                    display_acl("DACL", parsed_sddl['D'])
                
                if 'S' in parsed_sddl:
                    display_acl("SACL", parsed_sddl['S'])
                
                st.markdown("### 📊 Security Impact Analysis")
                summary = generate_sddl_summary(sddl_input)
                st.write(summary['impact'])

        st.header("Parse SDDL Examples")
        selected_example = st.selectbox("Select an example", options=list(SDDL_EXAMPLES.keys()))

        if selected_example:
            example = SDDL_EXAMPLES[selected_example]
            st.info(example["description"])
            st.code(example["sddl"], language="text")

            st.subheader("Example Breakdown")
            parsed = parse_sddl(example["sddl"])

            if "O" in parsed:
                owner = TRUSTEES.get(parsed["O"], parsed["O"])
                st.write("🔑 **Owner:**", owner)
                st.write(f"*{get_trustee_description(parsed['O'])}*")

            if "G" in parsed:
                group = TRUSTEES.get(parsed["G"], parsed["G"])
                st.write("👥 **Primary Group:**", group)
                st.write(f"*{get_trustee_description(parsed['G'])}*")

            for section, content in parsed.items():
                if section in ['D', 'S']:
                    section_name = "DACL (Access Control)" if section == "D" else "SACL (Auditing)"
                    st.write(f"### {section_name}")

                    aces = [ace + ')' for ace in content.split(')') if ace.strip()]

                    for ace in aces:
                        if ace.strip('()'):
                            ace_data = get_ace_display_data(ace)
                            
                            if 'error' in ace_data:
                                st.error(f"⚠️ Error in ACE - {ace}: {ace_data['error']}")
                                continue

                            st.markdown(f"**📋 {ace_data['what']} - {ace_data['who']}**")
                            st.code(ace, language="text")
                            
                            col1, col2 = st.columns([1, 2])
                            with col1:
                                st.write("**Who:**")
                                st.write(ace_data['who'])
                                st.write(f"*{ace_data['who_details']}*")

                                st.write("**What:**")
                                st.write(ace_data.get('type_description', 'Unknown access type'))

                            with col2:
                                if ace_data.get('permissions'):
                                    st.write("**Permissions:**")
                                    for right in ace_data['permissions']:
                                        st.write(f"✓ {right['name']}")
                                        st.write(f"*{right['description']}*")

                                if ace_data.get('special_conditions'):
                                    st.write("**Special Conditions:**")
                                    for flag in ace_data['special_conditions']:
                                        st.write(f"⚡ {flag['name']}")
                                        st.write(f"*{flag['description']}*")
                            
                            st.markdown("---")

    with tab2:
        build_sddl()

    with tab3:
        st.header("SDDL Reference")

        st.subheader("ACE Types")
        for ace_type, description in ACE_TYPES.items():
            st.write(f"**{ace_type}**: {description}")

        st.subheader("ACE Flags")
        for flag, description in ACE_FLAGS.items():
            st.write(f"**{flag}**: {description}")

        st.subheader("Rights")
        for right, description in RIGHTS.items():
            st.write(f"**{right}**: {description}")

        st.subheader("Trustees")
        for trustee, description in TRUSTEES.items():
            st.write(f"**{trustee}**: {description}")

        st.subheader("Well-Known SIDs")
        for sid, description in WELL_KNOWN_SIDS.items():
            st.write(f"**{sid}**: {description}")

        st.header("SDDL Application")
        st.markdown("""
        ### How to Apply SDDL:
        
        1. **Using PowerShell:**
        ```powershell
        # Get the current ACL
        $acl = Get-Acl -Path "path_to_object"
        
        # Set the new SDDL
        $acl.SetSecurityDescriptorSddlForm("your_sddl_string")
        
        # Apply the new ACL
        Set-Acl -Path "path_to_object" -AclObject $acl
        ```
        
        2. **Using ICACLS:**
        ```bash
        # Set the owner
        icacls "path_to_object" /setowner "owner_name"
        
        # Grant permissions
        icacls "path_to_object" /grant "user:(permissions)"
        
        # Deny permissions
        icacls "path_to_object" /deny "user:(permissions)"
        
        # Reset permissions
        icacls "path_to_object" /reset
        
        # Apply new permissions
        icacls "path_to_object" /setowner "owner_name"
        ```
        
        3. **Using Win32 API:**
        ```cpp
        ConvertStringSecurityDescriptorToSecurityDescriptor()
        SetNamedSecurityInfo()
        ```
        
        ### Best Practices:
        
        1. **Before Applying:**
           - Document existing permissions
           - Create permission backups
           - Test in isolated environment
           - Validate SDDL syntax
        
        2. **During Application:**
           - Apply changes during maintenance windows
           - Monitor for immediate issues
           - Have rollback plan ready
        
        3. **After Applying:**
           - Verify permissions are correct
           - Test access for affected users
           - Document all changes
           - Monitor security logs
        
        ### Common Use Cases:
        
        1. **System Hardening**
           - Restricting sensitive file access
           - Protecting registry keys
           - Securing service configurations
        
        2. **Compliance Requirements**
           - Implementing regulatory controls
           - Standardizing permissions
           - Enabling required auditing
        
        3. **Active Directory Management**
           - Delegating admin rights
           - Protecting sensitive OUs
           - Managing GPO access
        
        4. **Application Security**
           - Securing app directories
           - Protecting configuration files
           - Managing service accounts
        """)

    with tab4:
        st.header("SDDL Structure Mind Map")
        
        github_image_url = "https://raw.githubusercontent.com/MHaggis/SDDLMaker/main/MindMap/SDDL%20Demystified%20Mind%20Map.png"
        
        try:
            st.image(github_image_url, 
                    caption="SDDL Structure Mind Map",
                    use_container_width=True)
        except Exception as e:
            st.error(f"Unable to load mind map image: {str(e)}")
            st.info("Please view the mind map using the links below.")
        
        st.markdown("""
        ### External Links
        View and download the mind map:
        
        - [SDDL Demystified Mind Map (PDF)](https://github.com/MHaggis/SDDLMaker/blob/main/MindMap/SDDL%20Demystified%20Mind%20Map.pdf)
        - [Mind Map Directory](https://github.com/MHaggis/SDDLMaker/tree/main/MindMap)
        """)

def process_ace(ace_str: str, ace_type: str):
    """Helper function to process and display ACE information."""
    ace_data = get_ace_display_data(ace_str)
    
    if not ace_data or 'error' in ace_data:
        st.error(f"Error processing ACE: {ace_str}")
        return
    
    st.code(ace_str, language="text")
    
    try:
        if '_' in ace_data['what']:
            access_type = "Allow" if ace_data['what'].startswith("ACCESS_ALLOWED") else "Deny" if ace_data['what'].startswith("ACCESS_DENIED") else ace_data['what']
        else:
            access_type = ace_data['what']
    except:
        access_type = "Unknown"
    
    st.markdown(f"**{access_type} - {ace_data.get('who', 'Unknown')}**")
    
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Type:**")
        st.write(ace_data.get('type_description', 'Unknown access type'))
        
        st.write("**Applied To:**")
        st.write(ace_data.get('who', 'Unknown'))
        st.write(f"*{ace_data.get('who_details', 'No details available')}*")
    
    with col2:
        if ace_data.get('permissions'):
            st.write("**Permissions:**" if ace_type == "DACL" else "**Audited Actions:**")
            for right in ace_data['permissions']:
                st.write(f"{'✓' if ace_type == 'DACL' else '📝'} {right['name']}")
                st.write(f"*{right['description']}*")
        
        if ace_data.get('special_conditions'):
            st.write("**Special Conditions:**")
            for flag in ace_data['special_conditions']:
                st.write(f"⚡ {flag['name']}")
                st.write(f"*{flag['description']}*")
    st.markdown("---")

def get_flag_descriptions(flags_str: str) -> List[Dict[str, str]]:
    """Break down compound flags and get their descriptions."""
    flag_details = []
    
    # Handle compound flags by breaking them into individual flags
    # For example: 'CIID' -> ['CI', 'ID']
    i = 0
    while i < len(flags_str):
        found = False
        for flag_code in ACE_FLAGS:
            if flags_str[i:].startswith(flag_code):
                flag_details.append({
                    'name': flag_code,
                    'description': ACE_FLAGS[flag_code]
                })
                i += len(flag_code)
                found = True
                break
        if not found:
            i += 1

    return flag_details

def display_acl(acl_type: str, acl_data: str):
    st.markdown(f"### 🔐 {acl_type}")
    
    with st.expander("View Raw ACL"):
        st.text_area(
            f"Raw {acl_type}",
            value=acl_data,
            height=100,
            disabled=True
        )
    
    with st.expander(f"{acl_type} Breakdown"):
        try:
            aces = [ace.strip() for ace in acl_data.split(')') if ace.strip()]
            
            for i, ace in enumerate(aces):
                if not ace.strip('()'):
                    continue
                    
                ace_str = f"{ace})" if not ace.endswith(')') else ace
                ace_data = get_ace_display_data(ace_str)
                
                if not ace_data:
                    continue
                
                if i > 0:
                    st.markdown("---")
                    
                icon = "✅" if "ALLOWED" in ace_data['what'] else "❌" if "DENIED" in ace_data['what'] else "📋"
                
                st.markdown(f"#### {icon} {ace_data['what']}")
                
                st.code(ace, language="text")
                
                col1, col2 = st.columns([1, 2])
                with col1:
                    st.markdown("**Who:**")
                    st.write(ace_data['who'])
                    trustee_desc = TRUSTEES.get(ace_data['who'], "Custom Principal")
                    st.markdown(f"*{trustee_desc}*")
                    
                    st.markdown("**What:**")
                    st.write(ace_data.get('type_description', 'Unknown access type'))
                    
                with col2:
                    if ace_data.get('permissions'):
                        st.markdown("**Permissions:**")
                        for right in ace_data['permissions']:
                            st.markdown(f"✓ **{right['name']}**")
                            st.markdown(f"*{right['description']}*")
                            
                    if ace_data.get('special_conditions'):
                        st.markdown("**Special Conditions:**")
                        ace_parts = parse_ace(ace)
                        flags_str = ace_parts['flags']
                        flags = get_flag_descriptions(flags_str)
                        flags = get_flag_descriptions(flags_str)
                        for flag in flags:
                            st.markdown(f"⚡ **{flag['name']}**")
                            st.markdown(f"*{flag['description']}*")
        except Exception as e:
            st.error(f"Error processing {acl_type}: {str(e)}")

    parsed_sddl = parse_sddl(acl_data)
    
    st.markdown("### 📝 Summary")
    
    summary_text = []
    summary_text.append("This SDDL defines permissions with the following key points:\n")
    
    context_type = None
    rights_found = set()
    for ace in parsed_sddl.get('dacl', []):
        rights = ace.get('rights', '')
        rights_found.update(parse_rights(rights))
    
    if any(right in CONTEXT_PERMISSIONS['FileSystem'] for right in rights_found):
        context_type = "File System"
    elif any(right in CONTEXT_PERMISSIONS['Registry'] for right in rights_found):
        context_type = "Registry"
    elif any(right in CONTEXT_PERMISSIONS['ActiveDirectory'] for right in rights_found):
        context_type = "Active Directory"
    else:
        context_type = "General"

    summary_text.append(f"• **Context**: This is a {context_type} security descriptor\n")
    
    owner = parsed_sddl.get('owner', 'Unknown')
    group = parsed_sddl.get('group', 'Unknown')
    summary_text.append(f"• **Owner & Group**: {TRUSTEES.get(owner, owner)} owns and {TRUSTEES.get(group, group)} controls this object\n")
    
    summary_text.append("• **Key Access Rights**:")
    if 'dacl' in parsed_sddl:
        for ace in parsed_sddl['dacl']:
            trustee = ace.get('trustee', '')
            rights = ace.get('rights', '')
            ace_type = ace.get('type', '')
            
            if trustee and rights:
                trustee_name = TRUSTEES.get(trustee, trustee)
                rights_desc = []
                
                for right in parse_rights(rights):
                    if context_type != "General":
                        right_desc = CONTEXT_PERMISSIONS[context_type].get(right, RIGHTS.get(right, right))
                    else:
                        right_desc = RIGHTS.get(right, right)
                    rights_desc.append(right_desc)
                
                action = "is denied" if ace_type.startswith('D') else "is granted"
                summary_text.append(f"  - {trustee_name} {action} {', '.join(rights_desc)}")
    
    inheritance_text = []
    for ace in parsed_sddl.get('dacl', []):
        flags = ace.get('flags', '')
        if flags:
            for flag in ACE_FLAGS:
                if flag in flags:
                    inheritance_text.append(f"  - {ACE_FLAGS[flag]}")
    
    if inheritance_text:
        summary_text.append("\n• **Inheritance**:")
        summary_text.extend(list(set(inheritance_text)))  # Remove duplicates
    
    if 'sacl' in parsed_sddl:
        summary_text.append("\n• **Auditing**:")
        audit_types = set()
        for ace in parsed_sddl['sacl']:
            flags = ace.get('flags', '')
            trustee = ace.get('trustee', '')
            if 'SA' in flags:
                audit_types.add(f"Success auditing enabled for {TRUSTEES.get(trustee, trustee)}")
            if 'FA' in flags:
                audit_types.add(f"Failure auditing enabled for {TRUSTEES.get(trustee, trustee)}")
        
        summary_text.extend(f"  - {audit_type}" for audit_type in audit_types)
    
    st.markdown("\n".join(summary_text))

    st.markdown("---")
    st.markdown("### 📊 Security Impact Analysis")
    
    summary = generate_sddl_summary(acl_data)
    
    col1, col2 = st.columns([1, 3])
    
    if summary['impact_level'] == 'High':
        col1.error("🚨 High")
    elif summary['impact_level'] == 'Moderate':
        col1.warning("⚠️ Moderate")
    else:
        col1.success("✅ Low")
    
    col2.write(summary['impact'])
    
    if summary['key_findings']:
        st.markdown("#### Key Findings:")
        for finding in summary['key_findings']:
            st.write(f"- {finding}")
    
    if summary['recommendations']:
        st.markdown("#### Recommendations:")
        for recommendation in summary['recommendations']:
            st.write(f"- {recommendation}")

def generate_sddl_summary(sddl_string: str) -> Dict[str, Any]:
    """Enhanced SDDL summary generation with impact analysis."""
    summary = {
        'impact_level': 'Moderate',
        'impact': 'Moderate impact - primarily grants access',
        'key_findings': [],
        'recommendations': []
    }
    
    if 'D:' in sddl_string: 
        dacl_part = sddl_string.split('D:')[1].split('S:')[0] if 'S:' in sddl_string else sddl_string.split('D:')[1]
        
        if any(high_risk in dacl_part for high_risk in ['GA', 'WD', 'WO']):
            summary['impact_level'] = 'High'
            summary['impact'] = 'High impact - includes powerful permissions that could affect system security'
            summary['key_findings'].append('Contains high-privilege permissions (Full Control, Write DAC, or Write Owner)')
            summary['recommendations'].append('Review if full control permissions are necessary')
            
        if 'D;' in dacl_part:
            summary['key_findings'].append('Contains explicit deny rules')
            summary['recommendations'].append('Verify deny rules are intended and properly ordered')
    
    if 'S:' in sddl_string:
        summary['key_findings'].append('Includes auditing rules (SACL)')
        summary['recommendations'].append('Ensure audit policy aligns with security requirements')
    
    return summary

if __name__ == "__main__":
    main()

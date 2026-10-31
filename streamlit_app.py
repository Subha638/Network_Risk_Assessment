import streamlit as st

st.set_page_config(
    page_title="AI Network Risk Assessment",
    page_icon="🛡️",
    layout="wide"
)

st.title("AI Network Risk Assessment")
st.write("Welcome to the Network Security Dashboard")

if st.button("Test Application"):
    st.success("Streamlit is working!")

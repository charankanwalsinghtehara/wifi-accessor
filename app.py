from __future__ import annotations

import streamlit as st

from config import APP_NAME
from pages.wifi_security import render_wifi_security
from pages.reports import render_reports
from pages.website_security import render_website_security

st.set_page_config(page_title=APP_NAME, page_icon='🛡️', layout='wide')

with st.sidebar:
    st.title(APP_NAME)
    st.caption('Authorized local Wi-Fi security assessment')

pages = st.navigation(
    [
        st.Page(render_wifi_security, title='Wi-Fi Security', default=True),
        st.Page(render_website_security, title='Website Security'),
        st.Page(render_reports, title='Reports'),
    ]
)
pages.run()

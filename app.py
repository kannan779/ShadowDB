import streamlit as st
import pandas as pd
import security
from database import query

st.set_page_config(page_title='ShadowDB', page_icon='🛡️', layout='wide')
st.title('🛡️ ShadowDB')
st.caption('Tamper-evident database auditing and insider-threat detection')

actor = st.sidebar.text_input('Demo actor', 'admin@shadowdb.local')
page = st.sidebar.radio('Console', ['Employees', 'Audit Explorer', 'Integrity Check', 'Security Alerts'])

if page == 'Employees':
    st.subheader('Protected employee records')
    employees = security.list_employees()
    st.dataframe(pd.DataFrame(employees), use_container_width=True, hide_index=True)
    with st.expander('Add employee'):
        with st.form('add'):
            data = {k: st.text_input(k.replace('_',' ').title()) for k in ('employee_code','full_name','department','email')}
            data['salary'] = st.number_input('Salary', min_value=0.0, value=50000.0)
            data['status'] = st.selectbox('Status', ['ACTIVE','SUSPENDED','TERMINATED'])
            if st.form_submit_button('Insert and audit'):
                try: security.add_employee(data, actor); st.success('Inserted. Trigger audit and version row created.'); st.rerun()
                except Exception as exc: st.error(str(exc))
    if employees:
        selected = st.selectbox('Employee to delete', employees, format_func=lambda x: f"{x['employee_id']} — {x['full_name']}")
        if st.button('Delete selected employee'):
            try: security.delete_employee(selected['employee_id'], actor); st.success('Deleted and preserved in the audit trail.'); st.rerun()
            except Exception as exc: st.error(str(exc))

elif page == 'Audit Explorer':
    st.subheader('Audit events and historical snapshots')
    audit = security.list_audit()
    st.dataframe(pd.DataFrame(audit), use_container_width=True, hide_index=True)
    deleted = [row for row in audit if row['operation'] == 'DELETE']
    if deleted:
        selected = st.selectbox('Deleted record to restore', deleted, format_func=lambda x: f"Audit #{x['audit_id']} — {x['old_snapshot']}")
        if st.button('Restore as a new audited insert'):
            try: security.restore_deleted(selected['audit_id'], actor); st.success('Restored. The new insert is now part of the audit chain.'); st.rerun()
            except Exception as exc: st.error(str(exc))

elif page == 'Integrity Check':
    st.subheader('SHA-256 audit-chain verification')
    results = security.verify_chain()
    ok = all(item['valid'] for item in results) if results else True
    (st.success if ok else st.error)(f"Chain status: {'VALID' if ok else 'TAMPER DETECTED'} ({len(results)} events checked)")
    st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)

else:
    st.subheader('Suspicious activity alerts')
    alerts = query('SELECT * FROM security_alerts ORDER BY detected_at DESC')
    st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)

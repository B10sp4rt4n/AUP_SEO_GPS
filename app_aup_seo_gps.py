# app_aup_seo_gps.py
# Ejecuta: streamlit run app_aup_seo_gps.py
import json, time, hmac, hashlib, os, requests
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import numpy as np
import pandas as pd
import streamlit as st
import datetime
import openai
from dotenv import load_dotenv

# libs opcionales
try:
    import dns.resolver
except Exception:
    dns = None
else:
    dns = dns

try:
    import networkx as nx
    import matplotlib.pyplot as plt
except Exception:
    nx = None; plt = None

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except Exception:
    service_account = None; build = None

load_dotenv()

st.set_page_config(page_title="AUP SEO + DNS GPS", page_icon="🛰️", layout="wide")
st.title("🛰️ AUP SEO + DNS GPS – Regenerado de ceros")
st.caption("GPS de rutas (DNS → CWV → Contenido), playbooks por sector, DNS scan, conectores Google y envío HMAC a n8n.")

# -----------------------------
# Utilidades
# -----------------------------
@dataclass
class Route:
    id: str
    name: str
    category: str  # DNS/CWV/CONTENT
    description: str
    cost_usd: float
    time_weeks: float
    base_impact: float
    prerequisites: List[str]

def dns_health_score(resolve_ms: int, ns_count: int, dnssec: bool, spf: bool, dmarc: bool) -> float:
    lat_comp = float(np.clip(1 - (resolve_ms - 50) / (800 - 50), 0, 1))
    red_comp = min(ns_count / 4, 1)
    sec_flags = sum([dnssec, spf, dmarc]) / 3
    return float(np.round((0.45*lat_comp + 0.25*red_comp + 0.30*sec_flags)*100, 1))

def traffic_lift_from_routes(routes_order: List[Route]) -> float:
    lift = 1.0
    decay = 0.9
    for i, r in enumerate(routes_order):
        step = 1 + (r.base_impact * (decay ** i))
        lift *= step
    return lift - 1

def revenue_impact(visits: int, conv_rate: float, aov: float, traffic_lift: float) -> Dict[str, float]:
    base_conversions = visits * conv_rate
    base_rev = base_conversions * aov
    new_visits = visits * (1 + traffic_lift)
    new_conversions = new_visits * conv_rate
    new_rev = new_conversions * aov
    return {
        "baseline_revenue": base_rev,
        "projected_revenue": new_rev,
        "incremental_revenue": new_rev - base_rev,
        "projected_visits": new_visits,
    }

def simple_priority(routes: List[Route], dns_score: float) -> List[Route]:
    dns_threshold = 70
    dns_routes = [r for r in routes if r.category == "DNS"]
    other = [r for r in routes if r.category != "DNS"]
    if dns_routes and dns_score < dns_threshold:
        first = dns_routes[0]
        rest = sorted(other, key=lambda r: (-(r.base_impact/max(r.cost_usd,1)), r.time_weeks))
        return [first] + rest
    return sorted(routes, key=lambda r: (-(r.base_impact/max(r.cost_usd,1)), r.time_weeks))

def sign_body_hmac_sha256(secret: str, body_obj: dict) -> str:
    body = json.dumps(body_obj, separators=(",",":"), ensure_ascii=False).encode("utf-8")
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

def recomendaciones_ia(row):
    prompt = f"""
    Eres un consultor experto en infraestructura web, DNS y optimización de sitios. Analiza el siguiente reporte técnico del dominio y genera recomendaciones prácticas, priorizadas y accionables para mejorar la salud y el rendimiento del sitio.

    - Prioriza las acciones según impacto y facilidad de implementación.
    - Si detectas riesgos críticos de seguridad o disponibilidad, adviértelos primero.
    - Si el score general es bajo, explica las recomendaciones en lenguaje sencillo, evitando tecnicismos.
    - Para cada recomendación, incluye una breve justificación del porqué es importante.

    Reporte técnico:
    {row.to_dict()}

    Responde solo con viñetas claras y directas.
    """
    # Obtener la API key desde st.session_state
    api_key = st.session_state.get("openai_api_key")
    if not api_key:
        st.error("Debes ingresar tu OpenAI API Key en la barra lateral.")
        return "[Falta OpenAI API Key]"
    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "system", "content": "Eres un consultor técnico experto."},
                  {"role": "user", "content": prompt}],
        max_tokens=300,
        temperature=0.2
    )
    return response.choices[0].message.content

def generar_recomendaciones(dns_row):
    recs = []
    if dns_row["Score"] < 70:
        recs.append("Mejorar la configuración DNS: aumenta el número de NS, activa DNSSEC, revisa SPF y DMARC.")
    if not dns_row["DNSSEC"]:
        recs.append("Activa DNSSEC para mayor seguridad.")
    if not dns_row["SPF"]:
        recs.append("Publica un registro SPF válido para proteger el correo.")
    if not dns_row["DMARC"]:
        recs.append("Publica un registro DMARC para evitar suplantación de identidad.")
    if dns_row["Latencia (ms)"] > 300:
        recs.append("Reduce la latencia DNS migrando a un proveedor más rápido o revisando la configuración actual.")
    if not recs:
        recs.append("¡Excelente! La configuración DNS es sólida. Mantén monitoreo periódico.")
    return recs

# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:
    st.header("Parámetros de negocio")
    visits = st.number_input("Visitas orgánicas/mes (baseline)", min_value=0, value=50000, step=1000)
    conv_rate = st.number_input("Tasa de conversión (0–1)", min_value=0.0, max_value=1.0, value=0.015, step=0.001, format="%.3f")
    aov = st.number_input("Ticket promedio (AOV) en USD", min_value=0.0, value=60.0, step=1.0)

    st.markdown("---")
    st.header("Sanidad DNS (manual)")
    dns_ms = st.slider("Latencia de resolución DNS (ms)", min_value=50, max_value=800, value=350, step=10)
    ns_count = st.slider("Cantidad de servidores NS", min_value=1, max_value=6, value=2, step=1)
    dnssec_flag = st.checkbox("DNSSEC activo", value=False)
    spf_flag = st.checkbox("SPF correcto", value=True)
    dmarc_flag = st.checkbox("DMARC publicado", value=False)


    st.markdown("---")
    st.header("Impactos relativos por ruta")
    impact_dns = st.slider("Impacto DNS", 0.0, 1.0, 0.10, 0.01)
    impact_cwv = st.slider("Impacto Core Web Vitals", 0.0, 1.0, 0.18, 0.01)
    impact_content = st.slider("Impacto Contenido/Cluster", 0.0, 1.0, 0.22, 0.01)

    st.markdown("---")
    st.header("🔑 OpenAI API Key")
    openai_api_key = st.text_input("Introduce tu OpenAI API Key", type="password", key="openai_api_key")

# -----------------------------
# Sectores y playbooks
# -----------------------------
SECTORS = ["Ecommerce", "Salud", "Automotriz", "SaaS/B2B", "Medios/Contenido"]
sector = st.sidebar.selectbox("Sector / Industria", SECTORS, index=0)

PLAYBOOKS = {
    "Ecommerce": {
        "DNS": [
            {"task": "Migrar a DNS gestionado (Cloudflare/Route53)", "owner": "DevOps", "tools": ["Cloudflare","Route53"], "success_criteria": "NS redundantes (>=2), latencia < 150ms, DNSSEC activo", "depends_on": []},
            {"task": "Publicar SPF y DMARC en dominio raíz", "owner": "IT", "tools": ["DNS","Email Provider"], "success_criteria": "SPF válido y DMARC policy >= quarantine", "depends_on": []}
        ],
        "CWV": [
            {"task": "Optimizar imágenes (WebP/AVIF)", "owner": "Frontend", "tools": ["Lighthouse","Image CDN"], "success_criteria": "LCP < 2.5s en mobile", "depends_on": []},
            {"task": "Reducir JS de terceros (tag manager)", "owner": "Frontend", "tools": ["Tag Manager"], "success_criteria": "INP p75 < 200ms", "depends_on": []}
        ],
        "CONTENT": [
            {"task": "Normalizar títulos y descripciones de productos", "owner": "SEO", "tools": ["CMS"], "success_criteria": "0 duplicados críticos", "depends_on": []},
            {"task": "Cluster transaccional (categorías + filtros)", "owner": "SEO", "tools": ["GSC","Keyword DB"], "success_criteria": "+15% CTR en queries de compra", "depends_on": []}
        ]
    },
    "Salud": {
        "DNS": [
            {"task": "Habilitar DNSSEC y monitoreo de latencia global", "owner": "DevOps", "tools": ["Cloudflare"], "success_criteria": "DNSSEC activo, p95 < 200ms", "depends_on": []}
        ],
        "CWV": [
            {"task": "Priorizar carga de contenido crítico (accesibilidad)", "owner": "Frontend", "tools": ["Lighthouse"], "success_criteria": "CLS < 0.1", "depends_on": []}
        ],
        "CONTENT": [
            {"task": "Contenido E-E-A-T (autores y fuentes clínicas)", "owner": "SEO/Med", "tools": ["CMS"], "success_criteria": "+20% tiempo en página", "depends_on": []}
        ]
    },
    "Automotriz": {
        "DNS": [
            {"task": "Redundancia NS multi-región", "owner": "DevOps", "tools": ["Cloudflare","Route53"], "success_criteria": ">= 3 NS, latencia < 150ms", "depends_on": []}
        ],
        "CWV": [
            {"task": "Lazy-load de galerías y comparadores", "owner": "Frontend", "tools": ["Lighthouse"], "success_criteria": "LCP < 2.8s", "depends_on": []}
        ],
        "CONTENT": [
            {"task": "Clusters comparativos (modelo vs modelo)", "owner": "SEO", "tools": ["GSC","Keyword DB"], "success_criteria": "+10% CTR en comparativas", "depends_on": []}
        ]
    },
    "SaaS/B2B": {
        "DNS": [
            {"task": "DMARC enforcement y BIMI (si aplica)", "owner": "IT", "tools": ["DNS","ESP"], "success_criteria": "DMARC=reject, BIMI válido", "depends_on": []}
        ],
        "CWV": [
            {"task": "Eliminar bloqueo de render por scripts analytics", "owner": "Frontend", "tools": ["Lighthouse"], "success_criteria": "INP p75 < 200ms", "depends_on": []}
        ],
        "CONTENT": [
            {"task": "Clusters por caso de uso e industria", "owner": "SEO/PMM", "tools": ["CMS"], "success_criteria": "+20% leads orgánicos", "depends_on": []}
        ]
    },
    "Medios/Contenido": {
        "DNS": [
            {"task": "Cache DNS agresivo y Anycast", "owner": "DevOps", "tools": ["Cloudflare"], "success_criteria": "p95 < 120ms", "depends_on": []}
        ],
        "CWV": [
            {"task": "Control de ads para estabilidad visual", "owner": "Frontend/Ads", "tools": ["Lighthouse","Ad Manager"], "success_criteria": "CLS < 0.1", "depends_on": []}
        ],
        "CONTENT": [
            {"task": "Topic clusters evergreen + noticias", "owner": "SEO/Editorial", "tools": ["CMS"], "success_criteria": "+25% sesiones orgánicas", "depends_on": []}
        ]
    }
}

# -----------------------------
# Rutas y cálculos
# -----------------------------
routes = [
    Route("R1","Camino seguro (DNS)","DNS","DNS gestionado, DNSSEC, NS redundantes, SPF/DMARC.",200.0,1.0,impact_dns,[]),
    Route("R2","Llantas de performance (CWV)","CWV","Optimización LCP/INP/CLS; imágenes y JS.",800.0,2.0,impact_cwv,["R1"]),
    Route("R3","Atajo de contenido (Clusters)","CONTENT","Títulos, enlazado y clúster transaccional.",600.0,3.0,impact_content,["R2"]),
]
dns_score = dns_health_score(dns_ms, ns_count, dnssec_flag, spf_flag, dmarc_flag)
ordered = simple_priority(routes, dns_score)
lift = traffic_lift_from_routes(ordered)
rev = revenue_impact(visits, conv_rate, aov, lift)

tab_dash, tab_dns, tab_google, tab_graph = st.tabs(["Dashboard","DNS Scan","Google (GSC/GA4)","Grafo AUP"])

# -----------------------------
# DASHBOARD
# -----------------------------
with tab_dash:
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("DNS Health (manual)", f"{dns_score}/100")
    c2.metric("Lift tráfico", f"{lift*100:.1f}%")
    c3.metric("Ingresos base", f"{rev['baseline_revenue']:,.0f}")
    c4.metric("Ingresos proyectados", f"{rev['projected_revenue']:,.0f}")
    st.divider()

    rows = []; acc=0.0
    for i, r in enumerate(ordered, start=1):
        step_lift = (1 + (r.base_impact*(0.9**(i-1)))) - 1
        step_new_visits = visits * (1 + step_lift)
        step_rev = step_new_visits * conv_rate * aov
        incr = step_rev - (visits*conv_rate*aov)
        roi = (incr - r.cost_usd) / max(r.cost_usd,1)
        acc += r.time_weeks
        rows.append({
            "Orden": i, "ID": r.id, "Ruta": r.name, "Categoría": r.category,
            "Impacto": round(r.base_impact,3), "Costo USD": r.cost_usd,
            "Semanas": r.time_weeks, "Lift step %": f"{step_lift*100:.1f}%",
            "Ingresos incr. step": round(incr,2), "ROI step": round(roi,2),
            "Acum semanas": round(acc,1), "Notas": r.description
        })
    st.subheader("Plan priorizado")
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

    # Playbook según sector
    tasks = []
    pb = PLAYBOOKS.get(sector, {})
    for r in ordered:
        cat = "DNS" if r.category=="DNS" else ("CWV" if r.category=="CWV" else "CONTENT")
        for t in pb.get(cat, []):
            x = dict(t); x.update({"route_id": r.id, "route_name": r.name, "category": cat})
            tasks.append(x)
    if tasks:
        st.markdown(f"### Playbook sugerido ({sector})")
        st.dataframe(pd.DataFrame(tasks), use_container_width=True)
        st.download_button("⬇️ Descargar playbook JSON",
            data=json.dumps({"sector":sector,"tasks":tasks}, indent=2),
            file_name="aup_seo_dns_playbook.json", mime="application/json")

    export_payload = {
        "inputs": {
            "visits": visits,
            "conversion_rate": conv_rate,
            "aov": aov,
            "dns": {
                "latency_ms": dns_ms,
                "ns_count": ns_count,
                "dnssec": dnssec_flag,
                "spf": spf_flag,
                "dmarc": dmarc_flag,
                "score": dns_score
            }
        },
        "ordered_plan": [asdict(r) for r in ordered],
        "kpis": {
            "traffic_lift_pct": round(lift*100, 2),
            "baseline_revenue": round(rev["baseline_revenue"], 2),
            "projected_revenue": round(rev["projected_revenue"], 2),
            "incremental_revenue": round(rev["incremental_revenue"], 2)
        },
        "sector": sector,
        "playbook": tasks
    }

    st.download_button("⬇️ Descargar plan JSON",
        data=json.dumps(export_payload, indent=2),
        file_name="aup_seo_dns_gps_plan.json", mime="application/json")

    st.markdown("---")
    st.subheader("Enviar a n8n firmado (HMAC)")
    n8n_url = st.text_input("n8n Webhook URL", value=os.getenv("N8N_URL","http://localhost:5678/webhook/gps/execute"))
    n8n_secret = st.text_input("N8N_HMAC_SECRET", value=os.getenv("N8N_HMAC_SECRET","cambia-esto"), type="password")
    if st.button("Enviar plan a n8n (HMAC)"):
        try:
            sig = sign_body_hmac_sha256(n8n_secret, export_payload)
            headers = {"Content-Type":"application/json","X-GPS-Signature":sig}
            resp = requests.post(n8n_url, headers=headers, data=json.dumps(export_payload, separators=(',',':'), ensure_ascii=False).encode('utf-8'), timeout=30)
            st.code(f"Status: {resp.status_code}\nBody: {resp.text}")
        except Exception as e:
            st.error(f"Error enviando a n8n: {e}")

# -----------------------------
# DNS SCAN
# -----------------------------
with tab_dns:
    st.subheader("DNS Scan en vivo")
    domain = st.text_input("Dominio", value="midominio.com")
    resolver_choice = st.selectbox("Resolver", ["por defecto","1.1.1.1 (Cloudflare)","8.8.8.8 (Google)"])
    def config_resolver():
        if dns is None: return None
        res = dns.resolver.Resolver()
        if resolver_choice.startswith("1.1.1.1"): res.nameservers = ["1.1.1.1"]
        elif resolver_choice.startswith("8.8.8.8"): res.nameservers = ["8.8.8.8"]
        res.timeout = 3; res.lifetime = 3
        return res
    if st.button("Ejecutar scan"):
        if dns is None:
            st.warning("Instala dnspython: pip install dnspython")
        else:
            res = config_resolver()
            results = {"A":[], "AAAA":[], "NS":[], "MX":[], "TXT":[]}
            lat_ms = None; dnssec_live=False; spf_live=False; dmarc_live=False
            try:
                t0=time.perf_counter(); a=res.resolve(domain,"A"); lat_ms=int((time.perf_counter()-t0)*1000); results["A"]=[r.to_text() for r in a]
            except Exception as e: results["A"]=[f"Error: {e}"]
            try:
                aaaa=res.resolve(domain,"AAAA"); results["AAAA"]=[r.to_text() for r in aaaa]
            except Exception as e: results["AAAA"]=[f"Error: {e}"]
            try:
                ns=res.resolve(domain,"NS"); results["NS"]=[r.to_text() for r in ns]
            except Exception as e: results["NS"]=[f"Error: {e}"]
            try:
                mx=res.resolve(domain,"MX"); results["MX"]=[r.to_text() for r in mx]
            except Exception as e: results["MX"]=[f"Error: {e}"]
            try:
                txt=res.resolve(domain,"TXT"); txts=[r.to_text().strip('\"') for r in txt]; results["TXT"]=txts; spf_live=any(t.lower().startswith("v=spf1") for t in txts)
            except Exception as e: results["TXT"]=[f"Error: {e}"]
            try:
                dmarc_domain=f"_dmarc.{domain}"; dmarc=res.resolve(dmarc_domain,"TXT"); dmt=[r.to_text().strip('\"') for r in dmarc]; dmarc_live=any(t.lower().startswith("v=dmarc1") for t in dmt)
            except Exception: dmarc_live=False
            try:
                ds=res.resolve(domain,"DS"); dnssec_live=len(ds)>0
            except Exception: dnssec_live=False
            ns_count_live=len([x for x in results["NS"] if not str(x).startswith("Error")])
            live_score = dns_health_score(lat_ms if lat_ms else 800, ns_count_live, dnssec_live, spf_live, dmarc_live)
            st.metric("Latencia (ms)", lat_ms if lat_ms else "N/A")
            st.metric("NS detectados", ns_count_live)
            st.metric("DNSSEC", "Sí" if dnssec_live else "No")
            st.metric("SPF", "Sí" if spf_live else "No")
            st.metric("DMARC", "Sí" if dmarc_live else "No")
            st.metric("DNS Health (live)", f"{live_score}/100")
            st.json(results)
            st.info("Nota: DNSSEC por DS es heurístico, una validación completa requiere cadena de confianza.")

    st.subheader("Escáner y Picker de dominios")
    domain = st.text_input("Dominio a escanear", value="midominio.com")
    observaciones = st.text_input("Observaciones (opcional)", value="")
    if st.button("Escanear dominio"):
        # Simula escaneo DNS (puedes reemplazar por tu función real)
        dns_data = {
            "Dominio": domain,
            "Latencia (ms)": 120,
            "NS": 2,
            "DNSSEC": True,
            "SPF": True,
            "DMARC": False,
            "Score": 85,
            "Fecha": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "Observaciones": observaciones
        }
        if "resultados_dns" not in st.session_state:
            st.session_state["resultados_dns"] = []
        st.session_state["resultados_dns"].append(dns_data)

    # Mostrar tabla de resultados y picker
    if "resultados_dns" in st.session_state and st.session_state["resultados_dns"]:
        df_dns = pd.DataFrame(st.session_state["resultados_dns"])
        st.dataframe(df_dns)
        dominio_elegido = st.selectbox("Selecciona un dominio para analizar:", df_dns["Dominio"].unique())
        row = df_dns[df_dns["Dominio"] == dominio_elegido].iloc[0]
        st.write(row)
        st.markdown("**Recomendaciones de optimización:**")
        for rec in generar_recomendaciones(row):
            st.write(f"- {rec}")
        if st.button("Obtener recomendaciones IA"):
            with st.spinner("Consultando IA..."):
                recs_ia = recomendaciones_ia(row)
                st.markdown("**Recomendaciones IA:**")
                st.write(recs_ia)
        st.download_button("Descargar reporte CSV", data=df_dns.to_csv(index=False), file_name="reporte_dns.csv", mime="text/csv")

# -----------------------------
# GOOGLE
# -----------------------------
with tab_google:
    st.subheader("Conectores Google – (opcional, usa CSV si no hay API)")
    st.caption("Configura st.secrets['gcp_service_account'] para GSC/GA4, o sube CSVs exportados.")
    # Por simplicidad, dejamos solo el uploader para esta versión
    gsc_csv = st.file_uploader("Sube CSV de Search Console", type=["csv"])
    if gsc_csv is not None:
        df = pd.read_csv(gsc_csv)
        st.dataframe(df.head(50), use_container_width=True)
    ga4_csv = st.file_uploader("Sube CSV de GA4", type=["csv"])
    if ga4_csv is not None:
        df = pd.read_csv(ga4_csv)
        st.dataframe(df.head(50), use_container_width=True)

# -----------------------------
# GRAFO
# -----------------------------
with tab_graph:
    st.subheader("Grafo AUP – dependencias")
    if nx is None or plt is None:
        st.warning("Instala: pip install networkx matplotlib")
    else:
        G = nx.DiGraph()
        G.add_node("AUP_DNS", score=float(dns_score))
        G.add_node("AUP_Rendimiento")
        G.add_node("AUP_Contenido")
        G.add_node("AUP_Usuario")
        G.add_node("AUP_Ranking")
        G.add_edges_from([("AUP_DNS","AUP_Rendimiento"),("AUP_Rendimiento","AUP_Usuario"),("AUP_Contenido","AUP_Usuario"),("AUP_Usuario","AUP_Ranking")])
        pos = nx.spring_layout(G, seed=42)
        fig = plt.figure(figsize=(6,4))
        nx.draw_networkx_nodes(G, pos, node_size=1200)
        nx.draw_networkx_edges(G, pos, arrows=True)
        nx.draw_networkx_labels(G, pos, font_size=10)
        st.pyplot(fig)

st.caption("© AUP SEO + DNS GPS — versión regenerada.")


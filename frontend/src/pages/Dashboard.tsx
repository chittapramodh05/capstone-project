import { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from "recharts";
import "./Dashboard.css";

export default function Dashboard() {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingText, setLoadingText] = useState("");
  const [error, setError] = useState("");
  const [containmentStatus, setContainmentStatus] = useState<{ [key: string]: string }>({});
  const [toastMsg, setToastMsg] = useState("");

  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [detailedThreats, setDetailedThreats] = useState<any[]>([]);
  const [summaryInsights, setSummaryInsights] = useState("");
  const [charts, setCharts] = useState<{
    attackDistribution: any[];
  } | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) navigate("/");
  }, [navigate]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setError("");
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Please select a CSV file to analyze.");
      return;
    }

    const token = localStorage.getItem("token");
    if (!token) return navigate("/");

    setLoading(true);
    setLoadingText("Ingesting dataset...");
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const t1 = setTimeout(() => setLoadingText("Running ML analysis..."), 800);
      const t2 = setTimeout(() => setLoadingText("Generating threat intelligence..."), 2000);

      const response = await axios.post(
        "http://localhost:5000/api/threats/upload",
        formData,
        { headers: { Authorization: `Bearer ${token}`, "Content-Type": "multipart/form-data" } }
      );
      
      clearTimeout(t1);
      clearTimeout(t2);

      setStats(response.data.stats);
      setDetailedThreats(response.data.detailedThreats);
      setSummaryInsights(response.data.summaryInsights);
      setCharts(response.data.charts);
    } catch (err: any) {
      console.error("UPLOAD ERROR:", err.response?.data || err.message);
      if (err.response?.status === 401) {
        localStorage.removeItem("token");
        navigate("/");
      } else {
        setError(err.response?.data?.message || "File analysis failed. Ensure it's a valid CSV.");
      }
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem("token");
    navigate("/");
  };

  // Incident Response Simulation
  const simulateContainment = (threatId: string, sourceIp: string, targetAsset: string) => {
    setContainmentStatus(prev => ({ ...prev, [threatId]: 'CONTAINING...' }));
    showToast(`Initializing containment protocol for IP: ${sourceIp}...`);

    setTimeout(() => {
      showToast(`Blocking IP ${sourceIp} at Edge Firewall...`);
      setTimeout(() => {
        showToast(`Isolating Host ${targetAsset} from internal subnets...`);
        setTimeout(() => {
          setContainmentStatus(prev => ({ ...prev, [threatId]: 'CONTAINED' }));
          showToast(`✅ Threat Contained.Admin notified via Slack / PagerDuty.`);

          // visually update threat severity to mitigated
          setDetailedThreats(prev => prev.map(t => t.id === threatId ? { ...t, severity: 'Mitigated' } : t));
        }, 1500);
      }, 1500);
    }, 1500);
  };

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(""), 4000);
  };

  // Visual Setup for Recharts
  const COLORS = { "Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e", "Mitigated": "#64748b" };
  const pieData = [
    { name: 'Critical', value: stats.critical }, { name: 'High', value: stats.high },
    { name: 'Medium', value: stats.medium }, { name: 'Low', value: stats.low }
  ].filter(d => d.value > 0);

  return (
    <div className="dashboard-layout">
      {/* Toast Notification for Incident Response */}
      {toastMsg && <div className="toast-notification">{toastMsg}</div>}

      <header className="soc-header">
        <div className="logo-container">
          <div className="pulse-dot"></div>
          <h1>Agentic AI SOC</h1>
        </div>
        <button onClick={logout} className="logout-btn">Disconnect Session</button>
      </header>

      <main className="dashboard-content">
        <section className="control-panel glass-panel">
          <div className="upload-wrapper">
            <h3>Ingest Traffic Logs (CSV)</h3>
            <div className="file-input-group">
              <input type="file" accept=".csv" onChange={handleFileChange} id="file-upload" className="file-input" />
              <label htmlFor="file-upload" className="file-label">
                {selectedFile ? selectedFile.name : "Browse Network Logs..."}
              </label>
              <button
                onClick={handleUpload}
                disabled={loading}
                className={`analyze-btn ${loading ? 'loading' : ''}`}
              >
                {loading ? loadingText : "RUN ANALYSIS"}
              </button>
            </div>
            {error && <div className="error-banner">{error}</div>}
          </div>
        </section>

        <section className="stats-grid">
          <div className="stat-card"><h4 className="text-glow-blue">Total Events</h4><div className="stat-value font-mono">{stats.total.toLocaleString()}</div></div>
          <div className="stat-card critical-card"><h4 className="text-glow-red">Critical</h4><div className="stat-value font-mono">{stats.critical.toLocaleString()}</div></div>
          <div className="stat-card high-card"><h4 className="text-glow-orange">High</h4><div className="stat-value font-mono">{stats.high.toLocaleString()}</div></div>
          <div className="stat-card medium-card"><h4 className="text-glow-yellow">Medium</h4><div className="stat-value font-mono">{stats.medium.toLocaleString()}</div></div>
          <div className="stat-card low-card">
            <h4>Low Risk</h4>
            <div className="stat-value text-glow-green">{stats.low.toLocaleString()}</div>
          </div>
        </section>

        {charts && (
          <section className="charts-container">
            <div className="chart-card glass-panel">
              <h3>Severity Distribution</h3>
              <div className="chart-wrapper">
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                      {pieData.map((entry, index) => <Cell key={`cell - ${index} `} fill={COLORS[entry.name as keyof typeof COLORS]} />)}
                    </Pie>
                    <RechartsTooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="chart-card glass-panel">
              <h3>Attack Types Matrix</h3>
              <div className="chart-wrapper">
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={charts.attackDistribution} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={true} vertical={false} />
                    <XAxis type="number" stroke="#94a3b8" />
                    <YAxis dataKey="name" type="category" stroke="#94a3b8" width={100} tick={{ fontSize: 11 }} />
                    <RechartsTooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                    <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

          </section>
        )}

        {summaryInsights && (
          <section className="insights-panel glass-panel">
            <h3>🛡️ Executive Summary</h3>
            <p>{summaryInsights}</p>
          </section>
        )}

        <section className="threat-table-container glass-panel">
          <h3>Real-Time Threat Intelligence</h3>
          <div className="table-scroll-wrapper">
            {detailedThreats.length > 0 ? (
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Threat ID</th>
                    <th>Attack Vector</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>AI Context</th>
                    <th>Source IP</th>
                    <th>Target Asset</th>
                    <th>Action Workflow</th>
                  </tr>
                </thead>
                <tbody>
                  {detailedThreats.map((threat) => (
                    <tr key={threat.id} className={`row-severity-${threat.severity.toLowerCase()}`}>
                      <td className="font-mono">{threat.id}</td>
                      <td className="font-bold">{threat.attackType}</td>
                      <td><span className={`severity-pill pill-${threat.severity.toLowerCase()}`}>{threat.severity}</span></td>
                      <td className="font-mono text-glow-blue">{threat.probability || 'N/A'}</td>
                      <td className="text-sm italic" style={{color: '#94a3b8', maxWidth: '200px'}}>{threat.reason || 'Standard classification'}</td>
                      <td className="font-mono text-glow-red">{threat.sourceIp}</td>
                      <td className="font-bold">{threat.targetAsset}</td>
                      <td>
                        {threat.severity === 'Mitigated' ? (
                          <span className="text-glow-green font-bold">CONTAINED</span>
                        ) : (
                          <button
                            className={`contain-btn ${containmentStatus[threat.id] === 'CONTAINING...' ? 'btn-active' : ''}`}
                            onClick={() => simulateContainment(threat.id, threat.sourceIp, threat.targetAsset)}
                            disabled={!!containmentStatus[threat.id]}
                          >
                            {containmentStatus[threat.id] || "Launch Containment"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state"><p>Awaiting data ingestion. System standing by.</p></div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
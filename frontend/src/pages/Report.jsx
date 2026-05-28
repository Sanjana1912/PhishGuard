import { useEffect, useState } from "react"
import { useParams, Navigate } from "react-router-dom"
import Layout from "../components/Layout"
import ScanResultPanel from "../components/ScanResultPanel"
import API from "../services/api"

function Report() {
  const { scan_id } = useParams()
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!scan_id) {
      setError("Missing report id")
      setLoading(false)
      return
    }

    API.get(`/api/report/${scan_id}`)
      .then((res) => {
           console.log("REPORT DATA:", res.data)
           setReport(res.data)
})
      .catch((err) => {
        const status = err.response?.status
        if (status === 404) {
          setError("Report not found.")
        } else {
          setError("Failed to load report. Please try again.")
        }
      })
      .finally(() => setLoading(false))
  }, [scan_id])

  if (!scan_id) {
    return <Navigate to="/dashboard" replace />
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="panel p-6 border-cyan-500/20 shadow-[0_0_40px_rgba(34,211,238,0.06)]">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Threat Report</h1>
              <p className="text-sm text-slate-400 mt-1">
                Detailed scan result for report ID <span className="font-mono text-slate-200">{scan_id}</span>
              </p>
            </div>
            <span className="text-xs text-cyan-400/80 mono shrink-0">GET /api/report/{scan_id}</span>
          </div>

          {loading ? (
            <div className="text-slate-400">Loading report…</div>
          ) : error ? (
            <div className="text-sm text-red-300">{error}</div>
          ) : report ? (
            <ScanResultPanel scan={report} />
          ) : (
            <div className="text-slate-400">No report available.</div>
          )}
        </div>
      </div>
    </Layout>
  )
}

export default Report

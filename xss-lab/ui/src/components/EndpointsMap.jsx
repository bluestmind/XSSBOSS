import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

/**
 * EndpointsMap - A premium HTML5 Canvas Force-Directed Node Graph.
 * Visualizes targets, endpoints, parameter structures, and security findings.
 */
function EndpointsMap({ targetId, monitor }) {
  const canvasRef = useRef(null);
  
  // Graph Data States
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  
  // Filter and Control States
  const [showParams, setShowParams] = useState(true);
  const [showFindingsOnly, setShowFindingsOnly] = useState(false);
  const [showJsFiles, setShowJsFiles] = useState(true);
  const [repulsionStrength, setRepulsionStrength] = useState(150);
  
  // Canvas View States
  const transformRef = useRef({ x: 0, y: 0, scale: 1 });
  const mouseRef = useRef({ x: 0, y: 0, isDown: false, dragStart: { x: 0, y: 0 } });
  const draggedNodeRef = useRef(null);
  const hoveredNodeRef = useRef(null);
  const animationFrameRef = useRef(null);
  
  // ---------------------------------------------------------------------------
  // 1. Data Collection & Graph Construction
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let active = true;
    
    async function buildGraph() {
      let rawEndpoints = [];
      let rawParams = [];
      let rawFindings = [];
      let targetUrl = "Target Domain";

      if (monitor) {
        // Build live from monitor stream
        targetUrl = monitor.target.base_url;
        
        // Deduplicate endpoints and params from live checks
        const endpointMap = new Map();
        const paramMap = new Map();
        
        (monitor.recent_checks || []).forEach(check => {
          const epKey = `${check.endpoint_method} ${check.endpoint_url}`;
          if (!endpointMap.has(epKey)) {
            endpointMap.set(epKey, {
              id: `ep-${check.id}`,
              method: check.endpoint_method,
              url_pattern: check.endpoint_url,
              type: 'endpoint'
            });
          }
          
          if (check.param_name) {
            const paramKey = `${epKey} - ${check.param_name}`;
            if (!paramMap.has(paramKey)) {
              paramMap.set(paramKey, {
                id: `param-${check.id}-${check.param_name}`,
                endpointKey: epKey,
                name: check.param_name,
                location: check.param_location || 'query',
                type: 'param'
              });
            }
          }
        });
        
        rawEndpoints = Array.from(endpointMap.values());
        rawParams = Array.from(paramMap.values());
        rawFindings = (monitor.recent_findings || []).map((f, idx) => ({
          id: `finding-${f.id || idx}`,
          endpoint_url: f.endpoint_url,
          param_name: f.param_name,
          severity: f.severity,
          vuln_type: f.vuln_type || 'xss',
          payload: f.payload_preview,
          type: 'finding'
        }));
      } else if (targetId) {
        // Load static from database
        try {
          const epRes = await axios.get(`/api/v1/endpoints?target_id=${targetId}`);
          rawEndpoints = epRes.data;
          
          // Fetch parameters for each endpoint in parallel
          const paramPromises = rawEndpoints.map(ep => 
            axios.get(`/api/v1/params?endpoint_id=${ep.id}`).then(res => 
              res.data.map(p => ({ ...p, endpointKey: `${ep.method} ${ep.url_pattern}` }))
            )
          );
          const paramsList = await Promise.all(paramPromises);
          rawParams = paramsList.flat();
          
          // Set target hostname
          if (rawEndpoints.length > 0) {
            const parsed = new URL(rawEndpoints[0].url_pattern);
            targetUrl = parsed.origin;
          }
        } catch (error) {
          console.error("Failed to build static endpoints graph:", error);
        }
      } else {
        return;
      }

      if (!active) return;

      // Construct nodes & links lists
      const newNodes = [];
      const newLinks = [];
      
      // A. Center Target Node
      const rootId = 'root-target';
      newNodes.push({
        id: rootId,
        label: targetUrl,
        type: 'target',
        radius: 20,
        color: '#8b5cf6', // Indigo glow
        x: 0, y: 0, vx: 0, vy: 0
      });
      
      // B. Filter & Add Endpoint Nodes
      const validEpKeys = new Set();
      rawEndpoints.forEach(ep => {
        const isJs = ep.url_pattern.split('?')[0].endsWith('.js');
        if (!showJsFiles && isJs) return;
        
        // If showing findings only, verify this endpoint has findings attached
        if (showFindingsOnly) {
          const hasFinding = rawFindings.some(f => f.endpoint_url === ep.url_pattern);
          if (!hasFinding) return;
        }
        
        const epKey = `${ep.method} ${ep.url_pattern}`;
        validEpKeys.add(epKey);
        
        newNodes.push({
          id: `ep-${ep.id}`,
          label: ep.url_pattern,
          method: ep.method,
          type: 'endpoint',
          radius: 13,
          color: ep.method === 'POST' ? '#f43f5e' : '#3b82f6', // Rose for POST, blue for GET
          x: (Math.random() - 0.5) * 200,
          y: (Math.random() - 0.5) * 200,
          vx: 0, vy: 0
        });
        
        newLinks.push({
          source: rootId,
          target: `ep-${ep.id}`,
          length: 120,
          color: 'rgba(139, 92, 246, 0.2)'
        });
      });
      
      // C. Filter & Add Parameter Nodes
      if (showParams) {
        rawParams.forEach((param, idx) => {
          const epNode = rawEndpoints.find(e => `${e.method} ${e.url_pattern}` === param.endpointKey);
          if (!epNode || !validEpKeys.has(param.endpointKey)) return;
          
          const epNodeId = `ep-${epNode.id}`;
          const createdEpNode = newNodes.find(n => n.id === epNodeId);
          const refX = createdEpNode ? createdEpNode.x : 0;
          const refY = createdEpNode ? createdEpNode.y : 0;
          
          const paramNodeId = `param-${param.id || idx}`;
          newNodes.push({
            id: paramNodeId,
            label: `${param.name} (${param.location})`,
            name: param.name,
            location: param.location,
            type: 'param',
            radius: 8,
            color: '#f59e0b', // Amber/gold
            x: refX + (Math.random() - 0.5) * 60,
            y: refY + (Math.random() - 0.5) * 60,
            vx: 0, vy: 0
          });
          
          newLinks.push({
            source: epNodeId,
            target: paramNodeId,
            length: 60,
            color: 'rgba(245, 158, 11, 0.25)'
          });
          
          // D. Filter & Add Finding Nodes connected to Parameters
          rawFindings.forEach(f => {
            if (f.endpoint_url === epNode.url_pattern && f.param_name === param.name) {
              newNodes.push({
                id: f.id,
                label: `XSS (${f.severity})`,
                severity: f.severity,
                payload: f.payload,
                type: 'finding',
                radius: 11,
                color: '#ef4444', // Neon Crimson
                x: refX + (Math.random() - 0.5) * 90,
                y: refY + (Math.random() - 0.5) * 90,
                vx: 0, vy: 0
              });
              
              newLinks.push({
                source: paramNodeId,
                target: f.id,
                length: 45,
                color: 'rgba(239, 68, 68, 0.4)'
              });
            }
          });
        });
      }
      
      // Map string references to actual objects for links
      const nodeMap = new Map(newNodes.map(n => [n.id, n]));
      const resolvedLinks = [];
      newLinks.forEach(link => {
        const sourceNode = nodeMap.get(link.source);
        const targetNode = nodeMap.get(link.target);
        if (sourceNode && targetNode) {
          resolvedLinks.push({
            ...link,
            source: sourceNode,
            target: targetNode
          });
        }
      });
      
      setNodes(newNodes);
      setLinks(resolvedLinks);
    }
    
    buildGraph();
    
    return () => {
      active = false;
    };
  }, [targetId, monitor, showParams, showFindingsOnly, showJsFiles]);

  // ---------------------------------------------------------------------------
  // 2. Physics Simulation Loop
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (nodes.length === 0) return;
    
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    // Auto-resize canvas
    const handleResize = () => {
      canvas.width = canvas.parentElement.clientWidth;
      canvas.height = 500;
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    
    let isRunning = true;
    
    // Layout parameters
    const k_repulsion = repulsionStrength * 100;
    const k_attraction = 0.04;
    const k_gravity = 0.01;
    const damping = 0.85;
    
    function stepPhysics() {
      if (!isRunning) return;
      
      // A. Coulomb Repulsion
      for (let i = 0; i < nodes.length; i++) {
        const nodeA = nodes[i];
        if (nodeA === draggedNodeRef.current) continue;
        
        for (let j = i + 1; j < nodes.length; j++) {
          const nodeB = nodes[j];
          const dx = nodeB.x - nodeA.x;
          const dy = nodeB.y - nodeA.y;
          let dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 12) {
            // Overlap prevention: scatter them slightly
            nodeA.x -= (Math.random() - 0.5) * 10;
            nodeA.y -= (Math.random() - 0.5) * 10;
            dist = 12;
          }
          
          if (dist < 400) {
            const force = k_repulsion / (dist * dist);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            
            nodeA.vx -= fx;
            nodeA.vy -= fy;
            nodeB.vx += fx;
            nodeB.vy += fy;
          }
        }
      }
      
      // B. Hooke's Law Attraction along links
      links.forEach(link => {
        const dx = link.target.x - link.source.x;
        const dy = link.target.y - link.source.y;
        let dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 5) dist = 5;
        
        const force = k_attraction * (dist - link.length);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        
        if (link.source !== draggedNodeRef.current) {
          link.source.vx += fx;
          link.source.vy += fy;
        }
        if (link.target !== draggedNodeRef.current) {
          link.target.vx -= fx;
          link.target.vy -= fy;
        }
      });
      
      // C. Gravity (Centering force)
      nodes.forEach(node => {
        if (node === draggedNodeRef.current) return;
        
        const dx = 0 - node.x;
        const dy = 0 - node.y;
        node.vx += dx * k_gravity;
        node.vy += dy * k_gravity;
        
        // Update position
        node.x += node.vx;
        node.y += node.vy;
        node.vx *= damping;
        node.vy *= damping;
      });
      
      // D. Draw frame
      drawFrame();
      
      animationFrameRef.current = requestAnimationFrame(stepPhysics);
    }
    
    function drawFrame() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.save();
      
      // Apply zoom & pan transforms
      const t = transformRef.current;
      ctx.translate(canvas.width / 2 + t.x, canvas.height / 2 + t.y);
      ctx.scale(t.scale, t.scale);
      
      // 1. Draw Links
      links.forEach(link => {
        ctx.beginPath();
        ctx.moveTo(link.source.x, link.source.y);
        ctx.lineTo(link.target.x, link.target.y);
        ctx.strokeStyle = link.color;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });
      
      // 2. Draw Nodes
      nodes.forEach(node => {
        const isHovered = hoveredNodeRef.current === node;
        const isSelected = selectedNode === node;
        
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + (isHovered ? 2 : 0), 0, 2 * Math.PI);
        
        // Halo effect for Target and Finding nodes
        if (node.type === 'target') {
          const grad = ctx.createRadialGradient(node.x, node.y, node.radius, node.x, node.y, node.radius + 15);
          grad.addColorStop(0, 'rgba(139, 92, 246, 0.4)');
          grad.addColorStop(1, 'rgba(139, 92, 246, 0)');
          ctx.fillStyle = grad;
          ctx.arc(node.x, node.y, node.radius + 15, 0, 2 * Math.PI);
          ctx.fill();
        } else if (node.type === 'finding') {
          // Pulse pulsing animation
          const pulse = 4 + Math.sin(Date.now() / 150) * 3;
          ctx.fillStyle = 'rgba(239, 68, 68, 0.2)';
          ctx.arc(node.x, node.y, node.radius + pulse, 0, 2 * Math.PI);
          ctx.fill();
        }
        
        // Base Node Fill
        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
        ctx.fill();
        
        // Outline selected node
        if (isSelected) {
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 2.5;
          ctx.stroke();
        } else {
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
          ctx.lineWidth = 1;
          ctx.stroke();
        }
        
        // Display HTTP Method label for endpoints
        if (node.type === 'endpoint' && node.method) {
          ctx.fillStyle = '#ffffff';
          ctx.font = 'bold 8px monospace';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(node.method, node.x, node.y);
        }
        
        // Draw labels for root target & findings
        if (node.type === 'target' || node.type === 'finding') {
          ctx.fillStyle = '#1e293b';
          ctx.font = node.type === 'target' ? 'bold 12px sans-serif' : 'bold 10px sans-serif';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillText(node.label.length > 30 ? node.label.slice(0, 27) + '...' : node.label, node.x, node.y + node.radius + 5);
        }
      });
      
      // 3. Draw tooltip for hovered node
      if (hoveredNodeRef.current) {
        const node = hoveredNodeRef.current;
        ctx.restore(); // Draw tooltip in canvas space
        
        ctx.save();
        ctx.shadowColor = 'rgba(0, 0, 0, 0.15)';
        ctx.shadowBlur = 8;
        ctx.fillStyle = 'rgba(15, 23, 42, 0.9)'; // Dark slate tooltip
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
        ctx.lineWidth = 1;
        
        const pad = 10;
        const text = node.label;
        ctx.font = '11px sans-serif';
        const width = ctx.measureText(text).width + pad * 2;
        const height = 30;
        
        // Map node pos back to canvas coordinates
        const screenX = (node.x * t.scale) + canvas.width / 2 + t.x;
        const screenY = (node.y * t.scale) + canvas.height / 2 + t.y;
        
        const rx = screenX - width / 2;
        const ry = screenY - node.radius * t.scale - height - 10;
        
        // Draw tooltip box
        ctx.beginPath();
        ctx.roundRect(rx, ry, width, height, 6);
        ctx.fill();
        ctx.stroke();
        
        // Tooltip text
        ctx.fillStyle = '#ffffff';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, rx + width / 2, ry + height / 2);
        ctx.restore();
        ctx.save();
        ctx.translate(canvas.width / 2 + t.x, canvas.height / 2 + t.y);
        ctx.scale(t.scale, t.scale);
      }
      
      ctx.restore();
    }
    
    // Start loop
    animationFrameRef.current = requestAnimationFrame(stepPhysics);
    
    return () => {
      isRunning = false;
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameRef.current);
    };
  }, [nodes, links, selectedNode, repulsionStrength]);

  // ---------------------------------------------------------------------------
  // 3. Mouse Interaction Handlers
  // ---------------------------------------------------------------------------
  const getMousePos = (e) => {
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  };

  const toGraphCoords = (pos) => {
    const canvas = canvasRef.current;
    const t = transformRef.current;
    return {
      x: (pos.x - canvas.width / 2 - t.x) / t.scale,
      y: (pos.y - canvas.height / 2 - t.y) / t.scale
    };
  };

  const handleMouseDown = (e) => {
    const pos = getMousePos(e);
    const graphPos = toGraphCoords(pos);
    
    // Check if clicked a node
    let clickedNode = null;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const node = nodes[i];
      const dx = graphPos.x - node.x;
      const dy = graphPos.y - node.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < node.radius + 3) {
        clickedNode = node;
        break;
      }
    }
    
    if (clickedNode) {
      draggedNodeRef.current = clickedNode;
      setSelectedNode(clickedNode);
    } else {
      mouseRef.current.isDown = true;
      mouseRef.current.dragStart = { x: pos.x - transformRef.current.x, y: pos.y - transformRef.current.y };
    }
  };

  const handleMouseMove = (e) => {
    const pos = getMousePos(e);
    const graphPos = toGraphCoords(pos);
    
    if (draggedNodeRef.current) {
      draggedNodeRef.current.x = graphPos.x;
      draggedNodeRef.current.y = graphPos.y;
      draggedNodeRef.current.vx = 0;
      draggedNodeRef.current.vy = 0;
    } else if (mouseRef.current.isDown) {
      transformRef.current.x = pos.x - mouseRef.current.dragStart.x;
      transformRef.current.y = pos.y - mouseRef.current.dragStart.y;
    } else {
      // Find hovered node
      let foundHover = null;
      for (let i = nodes.length - 1; i >= 0; i--) {
        const node = nodes[i];
        const dx = graphPos.x - node.x;
        const dy = graphPos.y - node.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < node.radius + 3) {
          foundHover = node;
          break;
        }
      }
      hoveredNodeRef.current = foundHover;
    }
  };

  const handleMouseUp = () => {
    draggedNodeRef.current = null;
    mouseRef.current.isDown = false;
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const pos = getMousePos(e);
    const graphPos = toGraphCoords(pos);
    
    const zoomFactor = 1.1;
    const nextScale = e.deltaY < 0 
      ? transformRef.current.scale * zoomFactor 
      : transformRef.current.scale / zoomFactor;
      
    // Clamp zoom scale between 0.15 and 4
    const scale = Math.max(0.15, Math.min(4, nextScale));
    
    // Zoom centered on mouse pointer
    const canvas = canvasRef.current;
    transformRef.current.x = pos.x - canvas.width / 2 - graphPos.x * scale;
    transformRef.current.y = pos.y - canvas.height / 2 - graphPos.y * scale;
    transformRef.current.scale = scale;
  };

  const resetTransform = () => {
    transformRef.current = { x: 0, y: 0, scale: 1 };
    // Scatter nodes slightly to start animation
    nodes.forEach(n => {
      if (n.id !== 'root-target') {
        n.x = (Math.random() - 0.5) * 150;
        n.y = (Math.random() - 0.5) * 150;
      }
    });
  };

  // ---------------------------------------------------------------------------
  // 4. Render Component Layout
  // ---------------------------------------------------------------------------
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg shadow-xl overflow-hidden text-slate-100 flex flex-col h-[580px]">
      {/* Header bar */}
      <div className="bg-slate-950 border-b border-slate-800 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-md font-semibold text-slate-100 flex items-center gap-2">
            🕸️ Live Recon Achievement Graph
          </h2>
          <p className="text-xs text-slate-400">
            Interactive, force-directed network showing target endpoints, parameters, and findings.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <label className="flex items-center gap-1.5 cursor-pointer select-none">
            <input 
              type="checkbox" 
              checked={showParams} 
              onChange={e => setShowParams(e.target.checked)} 
              className="rounded border-slate-700 bg-slate-850 text-indigo-500 focus:ring-0 focus:ring-offset-0"
            />
            <span>Params</span>
          </label>
          <label className="flex items-center gap-1.5 cursor-pointer select-none">
            <input 
              type="checkbox" 
              checked={showJsFiles} 
              onChange={e => setShowJsFiles(e.target.checked)} 
              className="rounded border-slate-700 bg-slate-850 text-indigo-500 focus:ring-0 focus:ring-offset-0"
            />
            <span>JS Files</span>
          </label>
          <label className="flex items-center gap-1.5 cursor-pointer select-none">
            <input 
              type="checkbox" 
              checked={showFindingsOnly} 
              onChange={e => setShowFindingsOnly(e.target.checked)} 
              className="rounded border-slate-700 bg-slate-850 text-indigo-500 focus:ring-0 focus:ring-offset-0"
            />
            <span className="text-rose-400 font-semibold">Findings Only</span>
          </label>
          <button 
            type="button"
            onClick={resetTransform}
            className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-2.5 py-1 rounded"
          >
            Reset Layout
          </button>
        </div>
      </div>

      {/* Main Container */}
      <div className="flex-1 flex relative">
        <canvas 
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
          className="flex-1 cursor-grab active:cursor-grabbing"
        />

        {/* Dynamic Nodes Count Stats Overlay */}
        <div className="absolute top-4 left-4 flex flex-col gap-1.5 bg-slate-950/85 backdrop-blur border border-slate-800 rounded p-3 text-xs select-none">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-violet-500"></span>
            <span>Target: 1</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
            <span>Endpoints: {nodes.filter(n => n.type === 'endpoint').length}</span>
          </div>
          {showParams && (
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span>Parameters: {nodes.filter(n => n.type === 'param').length}</span>
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse"></span>
            <span className="text-rose-400 font-bold">Findings: {nodes.filter(n => n.type === 'finding').length}</span>
          </div>
        </div>

        {/* Node Metadata Inspector Panel */}
        <div className="w-[300px] bg-slate-950 border-l border-slate-800 p-5 overflow-y-auto text-xs flex flex-col gap-4">
          <h3 className="font-semibold text-slate-200 uppercase tracking-wider text-[10px] border-b border-slate-800 pb-2">
            Node Inspector
          </h3>
          {selectedNode ? (
            <div className="space-y-4">
              <div>
                <div className="text-[10px] text-slate-400 font-semibold uppercase">Type</div>
                <div className="text-sm font-bold capitalize mt-0.5 text-slate-100">{selectedNode.type}</div>
              </div>
              
              {selectedNode.type === 'target' && (
                <div>
                  <div className="text-[10px] text-slate-400 font-semibold uppercase">Root Domain</div>
                  <div className="text-xs font-mono font-bold mt-1 bg-slate-900 border border-slate-800 p-2 rounded text-indigo-400 break-all">
                    {selectedNode.label}
                  </div>
                </div>
              )}

              {selectedNode.type === 'endpoint' && (
                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">HTTP Method</div>
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold mt-1 ${
                      selectedNode.method === 'POST' ? 'bg-rose-500/10 border border-rose-500/20 text-rose-400' : 'bg-blue-500/10 border border-blue-500/20 text-blue-400'
                    }`}>
                      {selectedNode.method}
                    </span>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">URL Pattern</div>
                    <div className="text-xs font-mono mt-1 bg-slate-900 border border-slate-800 p-2 rounded text-slate-300 break-all select-all">
                      {selectedNode.label}
                    </div>
                  </div>
                </div>
              )}

              {selectedNode.type === 'param' && (
                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">Parameter Name</div>
                    <div className="text-sm font-bold text-amber-400 mt-0.5 font-mono">{selectedNode.name}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">Submission Location</div>
                    <span className="inline-block px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-bold text-slate-300 mt-1 capitalize">
                      {selectedNode.location}
                    </span>
                  </div>
                </div>
              )}

              {selectedNode.type === 'finding' && (
                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">Security Severity</div>
                    <span className="inline-block px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-[10px] font-bold text-rose-400 mt-1 uppercase">
                      {selectedNode.severity}
                    </span>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">Vulnerability Type</div>
                    <div className="text-xs font-semibold mt-1 text-blue-300">
                      {(selectedNode.vuln_type || 'xss').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase">Trigger Parameter</div>
                    <div className="text-xs font-mono font-bold mt-1 bg-slate-900 border border-slate-800 p-2 rounded text-slate-300">
                      {selectedNode.param_name || 'Controllable input'}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase font-bold text-rose-400">Trigger Payload (PoC)</div>
                    <div className="text-[11px] font-mono mt-1 bg-rose-950/20 border border-rose-500/20 p-2.5 rounded text-rose-300 break-all select-all whitespace-pre-wrap">
                      {selectedNode.payload || 'Browser trigger check'}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-slate-500 italic text-center py-10">
              Click any node in the graph to inspect detailed structural parameters and proof artifacts.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default EndpointsMap;

import { Injectable } from '@angular/core';
import cytoscape from 'cytoscape';

export interface CyElements {
  nodes: any[];
  edges: any[];
}

@Injectable({
  providedIn: 'root',
})
export class GraphRenderer {

  render(
    container: HTMLElement,
    elements: CyElements,
    layoutName: 'breadthfirst' | 'cose' = 'breadthfirst',
  ): any {

    const nodes = (elements?.nodes ?? []).map((node: any) => {
      const data = {
        ...(node.data || node),
      };

      data.displayLabel = this.makeNodeLabel(
        data.label ||
        data.name ||
        data.arn ||
        data.id ||
        'Unknown',
      );

      return {
        ...node,
        data,
      };
    });

    const edges = (elements?.edges ?? []).map((edge: any) => {
      const data = {
        ...(edge.data || edge),
      };

      data.displayLabel = this.makeEdgeLabel(
        data.label ||
        data.action ||
        data.kind ||
        '',
      );

      return {
        ...edge,
        data,
      };
    });

    return cytoscape({
      container,

      elements: [
        ...nodes,
        ...edges,
      ],

      minZoom: 0.35,
      maxZoom: 2.2,
      wheelSensitivity: 0.15,

      style: [
        /* =====================================================
           BASE NODE
           ===================================================== */
        {
          selector: 'node',
          style: {
            label: 'data(displayLabel)',

            width: 62,
            height: 62,

            'font-size': 11,
            'font-weight': 700,

            color: '#effff7',

            'text-wrap': 'wrap',
            'text-max-width': '130px',

            'text-valign': 'bottom',
            'text-halign': 'center',

            'text-margin-y': 14,

            'text-background-color': '#03100b',
            'text-background-opacity': 0.92,
            'text-background-padding': "4px",

            'text-outline-color': '#03100b',
            'text-outline-width': 2,

            'background-color': '#35ff94',

            'border-color': '#8affc2',
            'border-width': 2,

            'overlay-opacity': 0,
          },
        },

        /* =====================================================
           USER / PRINCIPAL
           ===================================================== */
        {
          selector: 'node[type="user"]',
          style: {
            'background-color': '#35ff94',
            'border-color': '#9dffd0',
            shape: 'ellipse',
          },
        },

        {
          selector: 'node[type="principal"]',
          style: {
            'background-color': '#35ff94',
            'border-color': '#9dffd0',
            shape: 'ellipse',
          },
        },

        /* =====================================================
           ROLE
           ===================================================== */
        {
          selector: 'node[type="role"]',
          style: {
            'background-color': '#b98cff',
            'border-color': '#d9c1ff',
            shape: 'round-rectangle',
          },
        },

        /* =====================================================
           POLICY
           ===================================================== */
        {
          selector: 'node[type="policy"]',
          style: {
            'background-color': '#ffd166',
            'border-color': '#ffe6a7',
            shape: 'diamond',
          },
        },

        /* =====================================================
           RESOURCE
           ===================================================== */
        {
          selector: 'node[type="resource"]',
          style: {
            'background-color': '#30d8ff',
            'border-color': '#9deeff',
            shape: 'round-rectangle',
          },
        },

        {
          selector: 'node[type="s3"]',
          style: {
            'background-color': '#30d8ff',
            'border-color': '#9deeff',
            shape: 'round-rectangle',
          },
        },

        /* =====================================================
           SELECTED NODE
           ===================================================== */
        {
          selector: 'node:selected',
          style: {
            'border-color': '#ffffff',
            'border-width': 4,

            'overlay-color': '#35ff94',
            'overlay-opacity': 0.12,
          },
        },

        /* =====================================================
           BASE EDGE
           ===================================================== */
        {
          selector: 'edge',
          style: {
            label: 'data(displayLabel)',

            width: 2,

            'line-color': '#246e54',

            'target-arrow-color': '#35ff94',
            'target-arrow-shape': 'triangle',

            'arrow-scale': 1.15,

            'curve-style': 'bezier',

            'font-size': 9,
            'font-weight': 600,

            color: '#9dcbbb',

            'text-background-color': '#03100b',
            'text-background-opacity': 0.96,
            'text-background-padding': "4px",

            'text-border-color': '#19553e',
            'text-border-width': 1,
            'text-border-opacity': 0.7,

            'text-rotation': 'autorotate',

            'source-text-offset': 20,
            'target-text-offset': 20,

            'overlay-opacity': 0,
          },
        },

        /* =====================================================
           ASSUME ROLE
           ===================================================== */
        {
          selector: 'edge[kind="assume_role"]',
          style: {
            'line-color': '#00dca6',
            'target-arrow-color': '#00dca6',

            width: 2.7,

            'line-style': 'solid',

            color: '#75f7d3',
          },
        },

        /* =====================================================
           PRIVILEGE ESCALATION
           ===================================================== */
        {
          selector: 'edge[kind="escalation"]',
          style: {
            'line-color': '#ff5d78',
            'target-arrow-color': '#ff5d78',

            'line-style': 'dashed',

            width: 3.2,

            color: '#ff9aae',
          },
        },

        {
          selector: 'edge[kind="privilege_escalation"]',
          style: {
            'line-color': '#ff5d78',
            'target-arrow-color': '#ff5d78',

            'line-style': 'dashed',

            width: 3.2,

            color: '#ff9aae',
          },
        },

        /* =====================================================
           OBSERVED EDGE
           ===================================================== */
        {
          selector: 'edge[kind="observed"]',
          style: {
            'line-color': '#34d9ff',
            'target-arrow-color': '#34d9ff',

            color: '#91ecff',
          },
        },
      ],

      layout:
        layoutName === 'cose'
          ? {
              name: 'cose',

              animate: false,

              fit: true,

              padding: 70,

              nodeRepulsion: 20000,

              idealEdgeLength: 210,

              edgeElasticity: 85,

              nestingFactor: 1.2,

              gravity: 0.15,

              numIter: 1800,

              initialTemp: 220,

              coolingFactor: 0.92,

              minTemp: 1,

              nodeDimensionsIncludeLabels: true,
            }
          : {
              name: 'breadthfirst',

              directed: true,

              fit: true,

              padding: 70,

              spacingFactor: 2.1,

              avoidOverlap: true,

              nodeDimensionsIncludeLabels: true,

              circle: false,
            },
    });
  }

  /**
   * Convert long AWS ARNs into short readable labels.
   *
   * Examples:
   *
   * arn:aws:iam::123456789012:role/deploy
   * => deploy
   *
   * arn:aws:s3:::acme-crown-jewels
   * => acme-crown-jewels
   */
  private makeNodeLabel(
    value: string,
  ): string {

    if (!value) {
      return 'Unknown';
    }

    let label = String(value).trim();

    /* S3 ARN */
    if (
      label.startsWith(
        'arn:aws:s3:::',
      )
    ) {
      label =
        label.replace(
          'arn:aws:s3:::',
          '',
        );
    }

    /* Generic AWS ARN */
    else if (
      label.startsWith('arn:')
    ) {

      const slashParts =
        label.split('/');

      if (
        slashParts.length > 1
      ) {
        label =
          slashParts[
            slashParts.length - 1
          ];
      } else {

        const colonParts =
          label.split(':');

        label =
          colonParts[
            colonParts.length - 1
          ];
      }
    }

    /*
     * Example:
     * resource:some-long-resource
     */
    if (
      label.includes(':') &&
      label.length > 32
    ) {

      const pieces =
        label.split(':');

      const finalPiece =
        pieces[
          pieces.length - 1
        ];

      if (finalPiece) {
        label = finalPiece;
      }
    }

    /*
     * Prevent labels from dominating
     * the graph.
     */
    if (
      label.length > 32
    ) {
      label =
        `${label.substring(
          0,
          29,
        )}…`;
    }

    return label;
  }

  /**
   * Convert raw edge labels into compact
   * SOC-friendly labels.
   */
  private makeEdgeLabel(
    value: string,
  ): string {

    if (!value) {
      return '';
    }

    const original =
      String(value).trim();

    const normalized =
      original
        .replace(
          /[^a-zA-Z]/g,
          '',
        )
        .toLowerCase();

    const labels:
      Record<string, string> = {

      assumerole:
        'AssumeRole',

      assumeroleobserved:
        'AssumeRole',

      escalation:
        'PrivEsc',

      privilegeescalation:
        'PrivEsc',

      observed:
        'Observed',

      getobject:
        'GetObject',

      s3getobject:
        'S3:GetObject',

      stoplogging:
        'StopLogging',

      createrole:
        'CreateRole',

      createpolicy:
        'CreatePolicy',

      attachrolepolicy:
        'AttachPolicy',

      putrolepolicy:
        'PutRolePolicy',

      updateassumerolepolicy:
        'UpdateTrust',

      updateassumerole:
        'UpdateTrust',

      passrole:
        'PassRole',

      iampassrole:
        'PassRole',

      listbucket:
        'ListBucket',

      putbucketpolicy:
        'BucketPolicy',

      getbucketpolicy:
        'GetBucketPolicy',

      deleteaccesskey:
        'DeleteKey',

      createaccesskey:
        'CreateKey',
    };

    if (
      labels[normalized]
    ) {
      return (
        labels[normalized]
      );
    }

    if (
      original.length > 24
    ) {
      return (
        `${original.substring(
          0,
          21,
        )}…`
      );
    }

    return original;
  }
}
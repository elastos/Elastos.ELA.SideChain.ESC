package opts

// BarChart
// https://echarts.apache.org/en/option.html#series-bar
type BarChart struct {
	// Name of stack. On the same category axis, the series with the
	// same stack name would be put on top of each other.
	Stack string

	// The gap between bars between different series, is a percent value like '30%',
	// which means 30% of the bar width.
	// Set barGap as '-100%' can overlap bars that belong to different series,
	// which is useful when putting a series of bar as background.
	// In a single coordinate system, this attribute is shared by multiple 'bar' series.
	// This attribute should be set on the last 'bar' series in the coordinate system,
	// then it will be adopted by all 'bar' series in the coordinate system.
	BarGap string

	// The bar gap of a single series, defaults to be 20% of the category gap,
	// can be set as a fixed value.
	// In a single coordinate system, this attribute is shared by multiple 'bar' series.
	// This attribute should be set on the last 'bar' series in the coordinate system,
	// then it will be adopted by all 'bar' series in the coordinate system.
	BarCategoryGap string

	// Index of x axis to combine with, which is useful for multiple x axes in one chart.
	XAxisIndex int

	// Index of y axis to combine with, which is useful for multiple y axes in one chart.
	YAxisIndex int
}

// BarData
// https://echarts.apache.org/en/option.html#series-bar.data
type BarData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`

	// The style setting of the text label in a single bar.
	Label *Label `json:"label,omitempty"`

	// ItemStyle settings in this series data.
	ItemStyle *ItemStyle `json:"itemStyle,omitempty"`

	// Tooltip settings in this series data.
	Tooltip *Tooltip `json:"tooltip,omitempty"`
}

// Bar3DChart is the option set for a 3D bar chart.
type Bar3DChart struct {
	// Shading is the coloring effect of 3D graphics in 3D Bar.
	// The following three coloring methods are supported in echarts-gl:
	// Options:
	//
	// * "color": Only display colors, not affected by other factors such as lighting.
	// * "lambert": Through the classic [lambert] coloring, can express the light and dark that the light shows.
	// * "realistic": Realistic rendering, combined with light.ambientCubemap and postEffect,
	//   can improve the quality and texture of the display.
	//   [Physical Based Rendering (PBR)] (https://www.marmoset.co/posts/physically-based-rendering-and-you-can-too/)
	//   is used in ECharts GL to represent realistic materials.
	Shading string
}

// BoxPlotData
// https://echarts.apache.org/en/option.html#series-boxplot.data
type BoxPlotData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`

	// The style setting of the text label in a single bar.
	Label *Label `json:"label,omitempty"`

	// ItemStyle settings in this series data.
	ItemStyle *ItemStyle `json:"itemStyle,omitempty"`

	// Emphasis settings in this series data.
	Emphasis *Emphasis `json:"emphasis,omitempty"`

	// Tooltip settings in this series data.
	Tooltip *Tooltip `json:"tooltip,omitempty"`
}

// EffectScatterData
// https://echarts.apache.org/en/option.html#series-effectScatter.data
type EffectScatterData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// FunnelData
// https://echarts.apache.org/en/option.html#series-funnel.data
type FunnelData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// GeoData
type GeoData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// GaugeData
// https://echarts.apache.org/en/option.html#series-gauge.data
type GaugeData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// GraphChart is the option set for graph chart.
// https://echarts.apache.org/en/option.html#series-graph
type GraphChart struct {
	// Graph layout.
	// * 'none' No layout, use x, y provided in node as the position of node.
	// * 'circular' Adopt circular layout, see the example Les Miserables.
	// * 'force' Adopt force-directed layout, see the example Force, the
	// detail about layout configurations are in graph.force
	Layout string

	// Force is the option set for graph force layout.
	Force *GraphForce

	// Whether to enable mouse zooming and translating. false by default.
	// If either zooming or translating is wanted, it can be set to 'scale' or 'move'.
	// Otherwise, set it to be true to enable both.
	Roam bool

	// Whether to focus/highlight the hover node and it's adjacencies.
	FocusNodeAdjacency bool

	// The categories of node, which is optional. If there is a classification of nodes,
	// the category of each node can be assigned through data[i].category.
	// And the style of category will also be applied to the style of nodes. categories can also be used in legend.
	Categories []*GraphCategory
}

// GraphNode represents a data node in graph chart.
// https://echarts.apache.org/en/option.html#series-graph.data
type GraphNode struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// x value of node position.
	X float32 `json:"x,omitempty"`

	// y value of node position.
	Y float32 `json:"y,omitempty"`

	// Value of data item.
	Value float32 `json:"value,omitempty"`

	// If node are fixed when doing force directed layout.
	Fixed bool `json:"fixed,omitempty"`

	// Index of category which the data item belongs to.
	Category int `json:"category,omitempty"`

	// Symbol of node of this category.
	// Icon types provided by ECharts includes
	// 'circle', 'rect', 'roundRect', 'triangle', 'diamond', 'pin', 'arrow', 'none'
	// It can be set to an image with 'image://url' , in which URL is the link to an image, or dataURI of an image.
	Symbol string `json:"symbol,omitempty"`

	// node of this category symbol size. It can be set to single numbers like 10,
	// or use an array to represent width and height. For example, [20, 10] means symbol width is 20, and height is10.
	SymbolSize interface{} `json:"symbolSize,omitempty"`

	// The style of this node.
	ItemStyle *ItemStyle `json:"itemStyle,omitempty"`
}

// GraphLink represents relationship between two data nodes.
// https://echarts.apache.org/en/option.html#series-graph.links
type GraphLink struct {
	// A string representing the name of source node on edge. Can also be a number representing the node index.
	Source interface{} `json:"source,omitempty"`

	// A string representing the name of target node on edge. Can also be a number representing node index.
	Target interface{} `json:"target,omitempty"`

	// value of edge, can be mapped to edge length in force graph.
	Value float32 `json:"value,omitempty"`
}

// GraphCategory represents a category for data nodes.
// The categories of node, which is optional. If there is a classification of nodes,
// the category of each node can be assigned through data[i].category.
// And the style of category will also be applied to the style of nodes. categories can also be used in legend.
// https://echarts.apache.org/en/option.html#series-graph.categories
type GraphCategory struct {
	// Name of category, which is used to correspond with legend and the content of tooltip.
	Name string `json:"name"`

	// The label style of node in this category.
	Label *Label `json:"label,omitempty"`
}

// HeatMapChart is the option set for a heatmap chart.
// https://echarts.apache.org/en/option.html#series-heatmap
type HeatMapChart struct {
	// Index of x axis to combine with, which is useful for multiple x axes in one chart.
	XAxisIndex int

	// Index of y axis to combine with, which is useful for multiple y axes in one chart.
	YAxisIndex int
}

// HeatMapData
// https://echarts.apache.org/en/option.html#series-heatmap.data
type HeatMapData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// KlineData
// https://echarts.apache.org/en/option.html#series-candlestick.data
type KlineData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// LineChart is the options set for a line chart.
// https://echarts.apache.org/en/option.html#series-line
type LineChart struct {
	// If stack the value. On the same category axis, the series with the same stack name would be put on top of each other.
	// The effect of the below example could be seen through stack switching of toolbox on the top right corner:
	Stack string

	// Whether to show as smooth curve.
	// If is typed in boolean, then it means whether to enable smoothing. If is
	// typed in number, valued from 0 to 1, then it means smoothness. A smaller value makes it less smooth.
	Smooth bool

	// Whether to show as a step line. It can be true, false. Or 'start', 'middle', 'end'.
	// Which will configure the turn point of step line.
	Step bool

	// Index of x axis to combine with, which is useful for multiple x axes in one chart.
	XAxisIndex int

	// Index of y axis to combine with, which is useful for multiple y axes in one chart.
	YAxisIndex int

	// Whether to connect the line across null points.
	ConnectNulls bool
}

// LineData
// https://echarts.apache.org/en/option.html#series-line.data
type LineData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`

	// Symbol of single data.
	// Icon types provided by ECharts includes 'circle', 'rect', 'roundRect', 'triangle', 'diamond', 'pin', 'arrow', 'none'
	// It can be set to an image with 'image://url' , in which URL is the link to an image, or dataURI of an image.
	Symbol string `json:"symbol,omitempty"`

	// single data symbol size. It can be set to single numbers like 10, or
	// use an array to represent width and height. For example, [20, 10] means symbol width is 20, and height is10
	SymbolSize int `json:"symbolSize,omitempty"`

	// Index of x axis to combine with, which is useful for multiple x axes in one chart.
	XAxisIndex int

	// Index of y axis to combine with, which is useful for multiple y axes in one chart.
	YAxisIndex int
}

// LiquidChart
// reference https://github.com/ecomfe/echarts-liquidfill
type LiquidChart struct {
	// Shape of single data.
	// Icon types provided by ECharts includes 'circle', 'rect', 'roundRect', 'triangle', 'diamond', 'pin', 'arrow', 'none'
	// It can be set to an image with 'image://url' , in which URL is the link to an image, or dataURI of an image.
	Shape string

	// Whether to show outline
	IsShowOutline bool

	// Whether to stop animation
	IsWaveAnimation bool
}

// LiquidData
// reference https://github.com/ecomfe/echarts-liquidfill
type LiquidData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// MapData
// https://echarts.apache.org/en/option.html#series-map.data
type MapData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// ParallelData
// https://echarts.apache.org/en/option.html#series-parallel.data
type ParallelData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// PieChart is the option set for a pie chart.
// https://echarts.apache.org/en/option.html#series-pie
type PieChart struct {
	// Whether to show as Nightingale chart, which distinguishes data through radius. There are 2 optional modes:
	// * 'radius' Use central angle to show the percentage of data, radius to show data size.
	// * 'area' All the sectors will share the same central angle, the data size is shown only through radiuses.
	RoseType string

	// Center position of Pie chart, the first of which is the horizontal position, and the second is the vertical position.
	// Percentage is supported. When set in percentage, the item is relative to the container width,
	// and the second item to the height.
	//
	// Example:
	//
	// Set to absolute pixel values ->> center: [400, 300]
	// Set to relative percent ->> center: ['50%', '50%']
	Center interface{}

	// Radius of Pie chart. Value can be:
	// * number: Specify outside radius directly.
	// * string: For example, '20%', means that the outside radius is 20% of the viewport
	// size (the little one between width and height of the chart container).
	//
	// Array.<number|string>: The first item specifies the inside radius, and the
	// second item specifies the outside radius. Each item follows the definitions above.
	Radius interface{}
}

// PieData
// https://echarts.apache.org/en/option.html#series-pie.data
type PieData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`

	// Whether the data item is selected.
	Selected bool `json:"selected,omitempty"`

	// The label configuration of a single sector.
	Label *Label `json:"label,omitempty"`

	// Graphic style of , emphasis is the style when it is highlighted, like being hovered by mouse, or highlighted via legend connect.
	ItemStyle *ItemStyle `json:"itemStyle,omitempty"`

	// tooltip settings in this series data.
	Tooltip *Tooltip `json:"tooltip,omitempty"`
}

// RadarData
// https://echarts.apache.org/en/option.html#series-radar
type RadarData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

// SankeyLink represents relationship between two data nodes.
// https://echarts.apache.org/en/option.html#series-sankey.links
type SankeyLink struct {
	// The name of source node of edge
	Source interface{} `json:"source,omitempty"`

	// The name of target node of edge
	Target interface{} `json:"target,omitempty"`

	// The value of edge, which decides the width of edge.
	Value float32 `json:"value,omitempty"`
}

// SankeyNode represents a data node.
// https://echarts.apache.org/en/option.html#series-sankey.nodes
type SankeyNode struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value string `json:"value,omitempty"`
}

// ScatterChart is the option set for a scatter chart.
// https://echarts.apache.org/en/option.html#series-scatter
type ScatterChart struct {
	// Index of x axis to combine with, which is useful for multiple x axes in one chart.
	XAxisIndex int

	// Index of x axis to combine with, which is useful for multiple y axes in one chart.
	YAxisIndex int
}

// ScatterData
// https://echarts.apache.org/en/option.html#series-scatter.data
type ScatterData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`

	// Symbol
	Symbol string `json:"symbol,omitempty"`

	// SymbolSize
	SymbolSize int `json:"symbolSize,omitempty"`

	// SymbolRotate
	SymbolRotate int `json:"symbolRotate,omitempty"`

	// Index of x axis to combine with, which is useful for multiple x axes in one chart.
	XAxisIndex int `json:"xAxisIndex,omitempty"`

	// Index of y axis to combine with, which is useful for multiple y axes in one chart.
	YAxisIndex int `json:"yAxisIndex,omitempty"`
}

// ThemeRiverData
// https://echarts.apache.org/en/option.html#series-themeRiver
type ThemeRiverData struct {
	// the time attribute of time and theme.
	Date string `json:"date,omitempty"`

	// the value of an event or theme at a time point.
	Value float64 `json:"value,omitempty"`

	// the name of an event or theme.
	Name string `json:"name,omitempty"`
}

// ToList converts the themeriver data to a list
func (trd ThemeRiverData) ToList() [3]interface{} {
	return [3]interface{}{trd.Date, trd.Value, trd.Name}
}

// WordCloudChart is the option set for a word cloud chart.
type WordCloudChart struct {
	// Shape of WordCloud
	// Optional: "circle", "rect", "roundRect", "triangle", "diamond", "pin", "arrow"
	Shape string

	// range of font size
	SizeRange []float32

	// range of font rotation angle
	RotationRange []float32
}

// WordCloudData
type WordCloudData struct {
	// Name of data item.
	Name string `json:"name,omitempty"`

	// Value of a single data item.
	Value interface{} `json:"value,omitempty"`
}

type Chart3DData struct {
	// Name of the data item.
	Name string `json:"name,omitempty"`

	// Value of the data item.
	// []interface{}{1, 2, 3}
	Value []interface{} `json:"value,omitempty"`

	// ItemStyle settings in this series data.
	ItemStyle *ItemStyle `json:"itemStyle,omitempty"`

	// The style setting of the text label in a single bar.
	Label *Label `json:"label,omitempty"`
}

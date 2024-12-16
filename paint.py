import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 1. 读取数据
file_path = 'output.xlsx'  # 替换为你的文件路径
df = pd.read_excel(file_path)

# 2. 选择你想分析的多列数据
columns_to_plot = ['Skewness of Intervals', 'Transfer Rate (B/s)', 'Duration (s)']  # 这里替换成你需要分析的列

# 3. 手动指定分桶的区间（可以根据每列的具体数据设置不同的区间）
custom_bins = {
    'Skewness of Intervals': [-5, 0, 1, 2, 3, 5, 10, 16, 60],
    'Transfer Rate (B/s)': [0, 100, 1000, 5000, 10000, 20000, 10000000],  # 示例区间，可以根据实际数据调整
    'Duration (s)': [0, 1, 2, 3, 4, 5, 7, 10, 15, 30, 50, 100, 170]
}

# 4. 创建多个子图
fig, axes = plt.subplots(len(columns_to_plot), 1, figsize=(10, 6 * len(columns_to_plot)))  # 根据列数自动生成子图

if len(columns_to_plot) == 1:
    axes = [axes]  # 如果只有一个列，确保axes仍然是一个列表

# 5. 遍历每列并绘制柱状图
for idx, column in enumerate(columns_to_plot):
    skewness_data = df[column]  # 获取当前列的数据
    bins = custom_bins[column]  # 获取对应的区间

    # 计算分桶统计
    hist, bin_edges = np.histogram(skewness_data, bins=bins)

    # 设置相同的条形宽度
    bar_width = 0.8  # 统一的宽度（可以根据需求调整）

    # 在子图中绘制当前列的柱状图
    ax = axes[idx]
    # 为每个区间绘制条形
    for i in range(len(hist)):
        ax.bar(i, hist[i], width=bar_width, align='center', edgecolor='black', alpha=0.7)

    # 设置标题、标签和网格
    ax.set_title(f'Histogram of {column}')
    ax.set_xlabel(column)
    ax.set_ylabel('Frequency')
    ax.grid(True)

    # 设置 X 轴刻度，显示区间的分组标签
    bin_labels = [f'[{bin_edges[i]:.1f}, {bin_edges[i+1]:.1f})' for i in range(len(bin_edges)-1)]  # 区间标签
    ax.set_xticks(range(len(bin_labels)))  # 设置 X 轴的刻度为每个区间的索引
    ax.set_xticklabels(bin_labels, rotation=45)  # 设置刻度标签为区间的名称

# 调整布局，防止子图重叠
plt.tight_layout()

# 显示所有柱状图
plt.show()

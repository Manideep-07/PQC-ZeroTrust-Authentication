% PQC Benchmarking Visualization Script
% This script reads benchmark_results.csv and generates a latency distribution plot.

% 1. Load Data
filename = 'benchmark_results.csv';
if ~exist(filename, 'file')
    fprintf('Error: %s not found. Run benchmark_pqc.py first.\n', filename);
    return;
end

data = readtable(filename);

% 2. Extract Fields
iterations = data.iteration;
latency = data.latency_ms;

% 3. Create Figure
figure('Color', [1 1 1], 'Position', [100 100 800 500]);
hold on;

% Plot latency over iterations
plot(iterations, latency, '-o', 'LineWidth', 1.5, 'MarkerSize', 6, ...
    'Color', [0 0.4470 0.7410], 'DisplayName', 'Handshake Latency');

% Plot Average Line
avg_latency = mean(latency);
line([min(iterations) max(iterations)], [avg_latency avg_latency], ...
    'Color', [0.8500 0.3250 0.0980], 'LineStyle', '--', 'LineWidth', 2, ...
    'DisplayName', sprintf('Average (%.2f ms)', avg_latency));

% 4. Formatting
grid on;
ax = gca;
ax.FontSize = 12;
ax.GridAlpha = 0.3;

xlabel('Iteration Number', 'FontWeight', 'bold');
ylabel('Latency (milliseconds)', 'FontWeight', 'bold');
title('Post-Quantum Zero Trust Handshake Performance', 'FontSize', 14);
legend('Location', 'northeast');

% 5. Statistical Summary (Annotation)
stats_str = {
    sprintf('Mean: %.2f ms', mean(latency)), ...
    sprintf('Std Dev: %.2f ms', std(latency)), ...
    sprintf('Max: %.2f ms', max(latency)), ...
    sprintf('Min: %.2f ms', min(latency))
};
annotation('textbox', [0.15 0.7 0.2 0.2], 'String', stats_str, ...
    'FitBoxToText', 'on', 'BackgroundColor', 'white', 'EdgeColor', [0.8 0.8 0.8]);

fprintf('Visualization generated successfully.\n');
hold off;

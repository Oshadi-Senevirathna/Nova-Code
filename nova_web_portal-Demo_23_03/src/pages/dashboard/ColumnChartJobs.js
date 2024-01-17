import { useState, useEffect } from 'react';
// material-ui
import { useTheme } from '@mui/material/styles';
// third-party
import ReactApexChart from 'react-apexcharts';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';

// chart options
const columnChartOptions = {
    chart: {
        width: 300,
        type: 'bar',
        toolbar: {
            show: false
        }
    },
    dataLabels: {
        enabled: true
    },
    tooltip: {
        theme: 'light'
    },
    legend: {
        position: 'bottom'
    },
    responsive: [
        {
            breakpoint: 480,
            options: {
                chart: {
                    width: 200
                },
                legend: {
                    position: 'bottom'
                }
            }
        }
    ]
};

// ==============================|| SALES COLUMN CHART ||============================== //

const ColumnChartJobs = ({ colors }) => {
    const theme = useTheme();

    const { primary, secondary } = theme.palette.text;
    const line = theme.palette.divider;

    const [options, setOptions] = useState(columnChartOptions);
    const [series, setSeries] = useState();
    const [labels, setLabels] = useState();

    useEffect(() => {
        const dataSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_FRONTEND_JOBS}>dashboard>job`).subscribe((data) => {
            if (data) {
                setOptions((prevState) => ({
                    ...prevState,
                    labels: data.labels,
                    colors: colors
                }));
                console.log(data.series, data.labels);
                var temp = [
                    {
                        name: 'All jobs',
                        data: data.series
                    }
                ];
                setSeries(temp);
                setLabels(data.labels);
            }
        });
        return () => {
            dataSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    return <>{series && labels && <ReactApexChart options={options} series={series} type="bar" labels={labels} height={300} />}</>;
};

export default ColumnChartJobs;

/* const SalesColumnChart = () => {
    const theme = useTheme();

    const { primary, secondary } = theme.palette.text;
    const line = theme.palette.divider;

    const warning = theme.palette.warning.main;
    const primaryMain = theme.palette.primary.main;
    const successDark = theme.palette.success.dark;

    const [series] = useState([
        {
            name: 'Net Profit',
            data: [180, 90, 135, 114, 120, 145]
        },
        {
            name: 'Revenue',
            data: [120, 45, 78, 150, 168, 99]
        }
    ]);

    const [options, setOptions] = useState(columnChartOptions);

    useEffect(() => {
        setOptions((prevState) => ({
            ...prevState,
            colors: [warning, primaryMain],
            xaxis: {
                labels: {
                    style: {
                        colors: [secondary, secondary, secondary, secondary, secondary, secondary]
                    }
                }
            },
            yaxis: {
                labels: {
                    style: {
                        colors: [secondary]
                    }
                }
            },
            grid: {
                borderColor: line
            },
            tooltip: {
                theme: 'light'
            },
            legend: {
                position: 'top',
                horizontalAlign: 'right',
                labels: {
                    colors: 'grey.500'
                }
            }
        }));
    }, [primary, secondary, line, warning, primaryMain, successDark]);

    return (
        <div id="chart">
            <ReactApexChart options={options} series={series} type="bar" height={430} />
        </div>
    );
}; */

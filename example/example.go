package main

import (
	"github.com/Nemo-G/go-gin-prometheus/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	/*	// Optional custom metrics list
		customMetrics := []*ginprometheus.Metric{
			&ginprometheus.Metric{
				ID:	"1234",				// optional string
				Name:	"test_metric",			// required string
				Description:	"Counter test metric",	// required string
				Type:	"counter",			// required string
			},
			&ginprometheus.Metric{
				ID:	"1235",				// Identifier
				Name:	"test_metric_2",		// Metric Name
				Description:	"Summary test metric",	// Help Description
				Type:	"summary", // type associated with prometheus collector
			},
			// Type Options:
			//	counter, counter_vec, gauge, gauge_vec,
			//	histogram, histogram_vec, summary, summary_vec
		}
		p := middleware.NewPrometheus("gin", customMetrics)
	*/

	router := gin.New()

	// prometheus middleware
	ginPrometheus := middleware.NewPrometheus("namespace_prefix")
	ginPrometheus.SetListenAddress(":4000")
	ginPrometheus.Use(router)

	// basic router
	// router.Use(basicMiddleWares()...)

}

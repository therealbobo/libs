include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(NOT EXISTS ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.grpc.pb.cc)
  file(TOUCH
      ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.grpc.pb.cc
      ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.pb.cc
  )
endif()

add_executable(fake_cri
    fake_cri.cpp
    ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.grpc.pb.cc
    ${CMAKE_BINARY_DIR}/libsinsp/cri-v1alpha2.pb.cc
)

add_dependencies(fake_cri sinsp)

include(protobuf)
include(grpc)
target_link_libraries(fake_cri
PRIVATE
  "${GRPC_LIBRARIES}"
  "${GRPCPP_LIB}"
  "${GRPC_LIB}"
  "${GPR_LIB}"
  "${PROTOBUF_LIB}"
  "${CARES_LIB}"
    pthread
    sinsp
    rt
)

target_include_directories(fake_cri
PRIVATE
  ${CMAKE_BINARY_DIR}
  ${PROTOBUF_INCLUDE}
)

#install(
#    FILES fake_cri_agent_container.pb
#          fake_cri_agent_pod.pb
#          fake_cri_agent_images.pb
#          fake_cri_agent_listcontainers.pb
#          fake_cri_crio_container.pb
#          fake_cri_crio_pod.pb
#          fake_cri_crio_images.pb
#          fake_cri_crio_listcontainers.pb
#    DESTINATION ${CMAKE_BINARY_DIR}/libsinsp_e2e_tests/resources/
#)

file(GLOB PROTOS "*.pb")
foreach(FILENAME IN LISTS PROTOS)
  configure_file(
    ${FILENAME}
    ${CMAKE_BINARY_DIR}/test/libsinsp_e2e/resources/
    COPYONLY
  )
endforeach()

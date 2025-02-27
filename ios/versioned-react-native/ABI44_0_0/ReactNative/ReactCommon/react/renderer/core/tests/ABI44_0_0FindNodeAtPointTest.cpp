/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <ABI44_0_0React/ABI44_0_0renderer/element/Element.h>
#include <ABI44_0_0React/ABI44_0_0renderer/element/testUtils.h>

#include "ABI44_0_0TestComponent.h"

using namespace ABI44_0_0facebook::ABI44_0_0React;

TEST(FindNodeAtPointTest, withoutTransform) {
  auto builder = simpleComponentBuilder();

  // clang-format off
  auto element =
    Element<ViewShadowNode>()
      .tag(1)
      .finalize([](ViewShadowNode &shadowNode){
        auto layoutMetrics = EmptyLayoutMetrics;
        layoutMetrics.frame.size = {1000, 1000};
        shadowNode.setLayoutMetrics(layoutMetrics);
      })
      .children({
        Element<ViewShadowNode>()
        .tag(2)
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {100, 100};
          layoutMetrics.frame.size = {100, 100};
          shadowNode.setLayoutMetrics(layoutMetrics);
        })
        .children({
          Element<ViewShadowNode>()
          .tag(3)
          .finalize([](ViewShadowNode &shadowNode){
            auto layoutMetrics = EmptyLayoutMetrics;
            layoutMetrics.frame.origin = {10, 10};
            layoutMetrics.frame.size = {10, 10};
            shadowNode.setLayoutMetrics(layoutMetrics);
          })
        })
    });
  
  auto parentShadowNode = builder.build(element);
  
  ABI44_0_0EXPECT_EQ(
            LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {115, 115})->getTag(), 3);
  ABI44_0_0EXPECT_EQ(LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {105, 105})->getTag(), 2);
  ABI44_0_0EXPECT_EQ(LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {900, 900})->getTag(), 1);
  ABI44_0_0EXPECT_EQ(
      LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {1001, 1001}), nullptr);
}

TEST(FindNodeAtPointTest, viewIsTranslated) {
  auto builder = simpleComponentBuilder();

  // clang-format off
  auto element =
    Element<ScrollViewShadowNode>()
      .tag(1)
      .finalize([](ScrollViewShadowNode &shadowNode){
        auto layoutMetrics = EmptyLayoutMetrics;
        layoutMetrics.frame.size = {1000, 1000};
        shadowNode.setLayoutMetrics(layoutMetrics);
      })
      .stateData([](ScrollViewState &data) {
        data.contentOffset = {100, 100};
      })
      .children({
        Element<ViewShadowNode>()
        .tag(2)
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {100, 100};
          layoutMetrics.frame.size = {100, 100};
          shadowNode.setLayoutMetrics(layoutMetrics);
        })
        .children({
          Element<ViewShadowNode>()
          .tag(3)
          .finalize([](ViewShadowNode &shadowNode){
            auto layoutMetrics = EmptyLayoutMetrics;
            layoutMetrics.frame.origin = {10, 10};
            layoutMetrics.frame.size = {10, 10};
            shadowNode.setLayoutMetrics(layoutMetrics);
          })
        })
    });
  
  auto parentShadowNode = builder.build(element);

  ABI44_0_0EXPECT_EQ(
      LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {15, 15})->getTag(),
      3);
  ABI44_0_0EXPECT_EQ(LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {5, 5})->getTag(), 2);
}

TEST(FindNodeAtPointTest, viewIsScaled) {
  auto builder = simpleComponentBuilder();

  // clang-format off
  auto element =
    Element<ViewShadowNode>()
      .tag(1)
      .finalize([](ViewShadowNode &shadowNode){
        auto layoutMetrics = EmptyLayoutMetrics;
        layoutMetrics.frame.size = {1000, 1000};
        shadowNode.setLayoutMetrics(layoutMetrics);
      })
      .children({
        Element<ViewShadowNode>()
        .tag(2)
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {100, 100};
          layoutMetrics.frame.size = {100, 100};
          shadowNode.setLayoutMetrics(layoutMetrics);
        })
        .children({
          Element<ViewShadowNode>()
          .tag(3)
          .props([] {
            auto sharedProps = std::make_shared<ViewProps>();
            sharedProps->transform = Transform::Scale(0.5, 0.5, 0);
            return sharedProps;
          })
          .finalize([](ViewShadowNode &shadowNode){
            auto layoutMetrics = EmptyLayoutMetrics;
            layoutMetrics.frame.origin = {10, 10};
            layoutMetrics.frame.size = {10, 10};
            shadowNode.setLayoutMetrics(layoutMetrics);
          })
        })
    });
  
  auto parentShadowNode = builder.build(element);

  ABI44_0_0EXPECT_EQ(
      LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {119, 119})->getTag(),
      2);
}

TEST(FindNodeAtPointTest, overlappingViews) {
  auto builder = simpleComponentBuilder();

  // clang-format off
  auto element =
    Element<ViewShadowNode>()
      .tag(1)
      .finalize([](ViewShadowNode &shadowNode){
        auto layoutMetrics = EmptyLayoutMetrics;
        layoutMetrics.frame.size = {100, 100};
        shadowNode.setLayoutMetrics(layoutMetrics);
      })
      .children({
        Element<ViewShadowNode>()
        .tag(2)
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {25, 25};
          layoutMetrics.frame.size = {50, 50};
          shadowNode.setLayoutMetrics(layoutMetrics);
        }),
        Element<ViewShadowNode>()
        .tag(3)
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {50, 50};
          layoutMetrics.frame.size = {50, 50};
          shadowNode.setLayoutMetrics(layoutMetrics);
        })
    });
  
  auto parentShadowNode = builder.build(element);
  
  ABI44_0_0EXPECT_EQ(
            LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {50, 50})->getTag(), 3);
}

TEST(FindNodeAtPointTest, overlappingViewsWithZIndex) {
  auto builder = simpleComponentBuilder();

  // clang-format off
  auto element =
    Element<ViewShadowNode>()
      .tag(1)
      .finalize([](ViewShadowNode &shadowNode){
        auto layoutMetrics = EmptyLayoutMetrics;
        layoutMetrics.frame.size = {100, 100};
        shadowNode.setLayoutMetrics(layoutMetrics);
      })
      .children({
        Element<ViewShadowNode>()
        .tag(2)
        .props([] {
          auto sharedProps = std::make_shared<ViewProps>();
          sharedProps->zIndex = 1;
          auto &yogaStyle = sharedProps->yogaStyle;
          yogaStyle.positionType() = ABI44_0_0YGPositionTypeAbsolute;
          return sharedProps;
        })
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {25, 25};
          layoutMetrics.frame.size = {50, 50};
          shadowNode.setLayoutMetrics(layoutMetrics);
        }),
        Element<ViewShadowNode>()
        .tag(3)
        .finalize([](ViewShadowNode &shadowNode){
          auto layoutMetrics = EmptyLayoutMetrics;
          layoutMetrics.frame.origin = {50, 50};
          layoutMetrics.frame.size = {50, 50};
          shadowNode.setLayoutMetrics(layoutMetrics);
        })
    });
  
  auto parentShadowNode = builder.build(element);
  
  ABI44_0_0EXPECT_EQ(
            LayoutableShadowNode::findNodeAtPoint(parentShadowNode, {50, 50})->getTag(), 2);
}


